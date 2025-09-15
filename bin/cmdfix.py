"""
cmdfix - Smart Command Stabilizer Daemon

A lightweight daemon that provides command correction, normalization, and learning
capabilities through a Unix domain socket interface.
"""

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path 
from typing import Dict, Any, Optional, List


"""This is the main daemon class for cmdfix."""
class CommandFixDaemon:
    def  __init__(self, socket_path: str = "/tmp/cmdfix.sock", config_path: str = "config/default_config.json", verbose: bool = False, foreground: bool = False):
        self.socket_path = socket_path
        self.config_path = config_path
        self.verbose = verbose
        self.foreground = foreground
        self.running = False
        self.server_socket = None

        # Static correction dictionary
        self.static_corrections: Dict[str, Any] = {}

        """
        Hardcoded dangerous commands for safety check
         - As in this can be passed through configurating files, we got to be careful and keep it out of user's reach.
         for now kept hardcoded for security purposes tho future updates can be added.

        """
        self.dangerous_commands = [
           "rm -rf /", "rm -rf /*", "rm -rf ~", "rm -rf .*",
            "dd if=/dev/zero", "dd if=/dev/random",
            "mkfs", "fdisk", "format",
            "sudo rm -rf", "chmod -R 000",
            ":(){ :|:& };:",  # Fork bomb
            "curl | sh", "wget | sh",
            "sudo dd", "dd of=/dev/sd"
        ]

        self._setup_logging()
        self._load_static_corrections()

    def _setup_logging(self):
        """
        Sets up logging for cmdfix daemon.

        If foreground is True, logging will be set up to print to the console.
        If foreground is False, logging will be set up to log to a file (/var/log/cmdfix.log).
        The log level is set to DEBUG if verbose is True, otherwise it is set to INFO.
        """
        log_level = logging.DEBUG if self.verbose else logging.INFO
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        if self.foreground:
            logging.basicConfig(level=log_level, format=log_format)
        else:
            # For daemon mode, log to syslog or file
            logging.basicConfig(filename='/var/log/cmdfix.log', level=log_level, format=log_format)
        self.logger = logging.getLogger('cmdfix')

    def _load_static_corrections(self):
        """
        Loads static corrections from a configuration file.

        Tries to open the configuration file and load the 'corrections' key from it.
        If the configuration file does not exist, it will create a default configuration file.
        If there is an error loading the configuration file, it will log the error and create a default configuration file.

        :raises: Exception
        """
        try:
            config_file = Path(self.config_path)
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.static_corrections = config.get('corrections', {})
                    self.logger.info(f"Loaded {len(self.static_corrections)} static corrections from {self.config_path}")
            else:
                self.logger.warning(f"Config file {self.config_path} not found")
                # creates default config file
                self._create_default_config()
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            self._create_default_config()

    
     def _create_default_config(self):
        """
        Creates a default configuration file for cmdfix daemon.

        The default configuration file will be created at the path specified by the --config option.
        The default configuration file contains a set of common case corrections, common typos, common shortcuts/aliases, Docker shortcuts, and system shortcuts.
        If the default configuration file already exists, this method will not overwrite it.
        If there is an error creating the default configuration file, this method will log the error.

        :raises: Exception
        """
        default_config = {
            "corrections": {
                # Case corrections
                "GIT": "git",
                "Git": "git",
                "CLEAR": "clear",
                "Clear": "clear",
                "LS": "ls",
                "Ls": "ls",
                "PWD": "pwd",
                "Pwd": "pwd",
                "CD": "cd",
                "Cd": "cd",
                
                # Common typos
                "rit": "git",
                "gti": "git",
                "gut": "git",
                "car": "cat",
                "claer": "clear",
                "cler": "clear",
                "sl": "ls",
                "grpe": "grep",
                "gerp": "grep",
                "les": "less",
                "mroe": "more",
                "mkdri": "mkdir",
                
                # Common shortcuts/aliases
                "gs": "git status",
                "ga": "git add",
                "gc": "git commit",
                "gp": "git push",
                "gl": "git log",
                "gd": "git diff",
                "gco": "git checkout",
                "gb": "git branch",
                "ll": "ls -la",
                "la": "ls -la",
                "l": "ls -l",
                "..": "cd ..",
                "...": "cd ../..",
                "....": "cd ../../..",
                
                # Docker shortcuts
                "d": "docker",
                "dc": "docker-compose",
                "dps": "docker ps",
                "di": "docker images",
                
                # System shortcuts
                "h": "history",
                "j": "jobs",
                "p": "ps aux",
                "df": "df -h",
                "du": "du -h",
                "free": "free -h",
                "mount": "mount | column -t"
            }
        }

        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(default_config,f,indent=2)
                self.static_corrections = default_config["corrections"]
            self.logger.info(f"Created default config file at {self.config_path}")
        except Exception as e:
            self.logger.error(f"Error creating default config: {e}")

    def _is_dangerous_command(self, command: str) -> bool:
        """
        Checks if a given command is potentially dangerous.

        This function checks if a given command contains any of the above
        dangerous commands. If a match is found, it returns True, otherwise
        it returns False.

        :param command: The command to check
        :type command: str
        :return: True if the command is dangerous, False otherwise
        :rtype: bool
        """
        command = command.lower().strip()

        for dangerous_cmd in self.dangerous_commands:
            if dangerous_cmd in command:
                return True

        return False

    def _process_command(self, command: str) -> Dict[str, Any]:
        """
        Processes a given command and returns a dictionary containing the command correction,
        whether the command requires confirmation and the type of match.

        :param command: The command to process
        :type command: str
        :return: A dictionary containing the command correction, whether the command requires confirmation and the type of match
        :rtype: Dict[str, Any]
        """
        command = command.strip()

        if not command:
            return {"corrections": None, "requires_confirm": False}

        # We Check for the exact match in static corrections
        if command in self.static_corrections:
            correction = self.static_corrections[command]
            requires_confirm = self._is_dangerous_command(correction)


            self.logger.debug(f"Static correction: '{command}' -> '{correction}'")
            return {"corrections": correction, "requires_confirm": requires_confirm, "match_type": "static"}
        
        #for now, if no static match found, return null
       self.logger.debug(f"No correction found for: '{command}'")
       return {"corrections": None, "requires_confirm": False}

    
    def _handle_client(self, client_socket, client_address):
        """
        Handles an incoming client connection.

        This function receives a command from the client, processes it and sends the JSON response back to the client.

        :param client_socket: The socket object for the client connection
        :type client_socket: socket.socket
        :param client_address: The address of the client
        :type client_address: tuple
        """
        try:
            self.logger.debug(f"Client Connected: {client_address}")

            # Receives command from client
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                return

            # we then process the command
            response = self._process_command(data)

            # We then send the JSON response back to the client
            response_json = json,dumps(response)
            client_socket.send(response_json.encode('utf-8'))

            self.logger.debug(f"Processed Command: '{data}' -> '{response}'")
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()


    def _cleanup_socket(self):
        """
        Cleans up the socket used by the daemon.

        This function is used to ensure that the socket is removed after the daemon has finished running.

        :raises: Exception
        """
        try:
            if os.path.exists(self.socket_path):
                os.unlike(self.socket_path)
                self.logger.info(f"Cleaned up socket: {self.socket_path}")
        except Exception as e:
            self.logger.error(f"Error cleaning up socket: {e}")

    def _signal_handler(self, signum, frame):
        """
        Signal handler for the daemon.

        This function is called when the daemon receives a signal from the operating system.
        It logs the signal received and shuts down the daemon.

        :param signum: The signal number received
        :type signum: int
        :param frame: The current stack frame
        :type frame: frame
        """
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()


     def start(self):
       
        """
        Starts the cmdfix daemon.

        This function starts the cmdfix daemon by setting up signal handlers,
        cleaning up any existing socket, creating a Unix domain socket,
        setting socket permissions, and entering the main server loop.

        :raises: Exception
        """
        self.logger.info("Starting cmdfix daemon...")
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Clean up any existing socket
        self._cleanup_socket()
        
        try:
            # Create Unix domain socket
            self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.server_socket.bind(self.socket_path)
            self.server_socket.listen(5)
            
            # Set socket permissions
            os.chmod(self.socket_path, 0o666)
            
            self.running = True
            self.logger.info(f"Daemon listening on {self.socket_path}")
            
            # Main server loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:  # Only log if we're not shutting down
                        self.logger.error(f"Error accepting client: {e}")
        
        except Exception as e:
            self.logger.error(f"Error starting daemon: {e}")
            sys.exit(1)
        
        finally:
            self._cleanup_socket()
    
    def stop(self):
        
    """
    Stops the daemon.

    This function stops the daemon by setting the running flag to False, closing the server socket and logging a message.

    :return: None
    :rtype: NoneType
    """
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.logger.info("Daemon stopped")


def daemonize():
    """
    Daemonizes the current process.

    This function will fork the current process twice, decouple from the parent environment,
    and redirect standard file descriptors to /dev/null.

    :raises: OSError
    """
    try:
        # First fork
        if os.fork() > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"First fork failed: {e}\n")
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)
    
    try:
        # Second fork
        if os.fork() > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Second fork failed: {e}\n")
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open('/dev/null', 'r') as si:
        os.dup2(si.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'w') as so:
        os.dup2(so.fileno(), sys.stdout.fileno())
    with open('/dev/null', 'w') as se:
        os.dup2(se.fileno(), sys.stderr.fileno())


def main():
    parser = argparse.ArgumentParser(description='cmdfix daemon - Smart Command Stabilizer')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('-f', '--foreground', action='store_true',
                       help='Run in foreground (don\'t daemonize)')
    parser.add_argument('-s', '--socket', default='/tmp/cmdfix.sock',
                       help='Unix socket path (default: /tmp/cmdfix.sock)')
    parser.add_argument('-c', '--config', default='config/default_config.json',
                       help='Configuration file path')
    parser.add_argument('--stop', action='store_true',
                       help='Stop running daemon')
    
    args = parser.parse_args()
    
    if args.stop:
        # we'll have something like this  success = stop_daemon(args.pid_file, args.socket)
        print("Stopping daemon functionality not yet implemented")
        sys.exit(0)
    
    # Create daemon instance
    daemon = CommandFixDaemon(
        socket_path=args.socket,
        config_path=args.config,
        verbose=args.verbose,
        foreground=args.foreground
    )
    
    # Daemonize if not running in foreground
    if not args.foreground:
        daemonize()
    
    try:
        daemon.start()
    except KeyboardInterrupt:
        daemon.stop()
    except Exception as e:
        logging.error(f"Daemon error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()