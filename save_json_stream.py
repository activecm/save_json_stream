#!/usr/bin/env python3
"""Reads lines from command-line-supplied filenames (or stdin if none) and saves them out to the appropriate zeek log file."""
#Tested under python3.  (Note, python 2 will not successfully parse the date string because of the time zone field at the end.)
#Copyright 2021, William Stearns <bill@activecountermeasures.com>
#Released under the GPL

import errno
import fileinput		#Allows one to read from files specified on the command line or read directly from stdin automatically
import argparse			#Processes command line arguments
import os
import socket			#Handles low-level network connections
import sys
import json			#parses json records received from the sensor
import ssl			#Allows a socket to be a TLS server if user chooses
from datetime import datetime	#Date field processing
import selectors		#Allows us to listen on multiple incoming network streams and process the next available without explicit polling
import getpass			#Lets us ask for a passphrase without echoing it to the screen


def to_str(bytes_or_str):
	"""Turn supplied value into a string."""
	if isinstance(bytes_or_str, bytes):											# pylint: disable=no-else-return
		return bytes_or_str.decode()
	else:
		return bytes_or_str



def mkdir_p(path):
	"""Create an entire directory branch.  Will not complain if the directory already exists."""

	if not os.path.isdir(path):
		try:
			os.makedirs(path)
		except OSError as exc:
			if exc.errno == errno.EEXIST and os.path.isdir(path):
				pass
			else:
				raise



def Debug(debug_message, should_show_debug):
	"""Warn user if debugging requested."""

	if should_show_debug:
		sys.stderr.write(debug_message + '\n')
		sys.stderr.flush()



def fail(fail_message):
	"""On a fatal error, notify user and exit."""

	sys.stderr.write(fail_message + ', exiting.\n')
	sys.stderr.flush()
	sys.exit(1)



def save_line_to_log(input_line, backup_sensor_name, output_directory, should_debug, should_reprint, should_limit_filenames, should_by_sensor):	# pylint: disable=too-many-arguments,too-many-branches,too-many-statements,too-many-locals
	"""Take the single input line and save it to the appropriate log file under the output_directory."""
	#Input line is a string, not bytes.

	if "input_lines" not in save_line_to_log.__dict__:
		save_line_to_log.input_lines = 0
	if "successful_writes" not in save_line_to_log.__dict__:
		save_line_to_log.successful_writes = 0
	if "alerts" not in save_line_to_log.__dict__:
		save_line_to_log.alerts = 0

	save_line_to_log.input_lines = save_line_to_log.input_lines + 1

	try:
		parsed_line = json.loads(input_line)		#Returns a nested python dictionary
	except json.decoder.JSONDecodeError:
		Debug("json parse error in: " + input_line, should_debug)
	else:
		if should_reprint:
			print(input_line)		#Removed "   , end=''  " as the corelight logs don't appear to have linefeeds for some reason

		if 'timestamp' in parsed_line:
			linestamp = parsed_line['timestamp']
			stampformat = "%Y-%m-%dT%H:%M:%S.%f%z"
		elif 'ts' in parsed_line:
			linestamp = parsed_line['ts']
			stampformat = "%Y-%m-%dT%H:%M:%S.%fZ"
		elif '_write_ts' in parsed_line:
			linestamp = parsed_line['_write_ts']
			stampformat = "%Y-%m-%dT%H:%M:%S.%fZ"
		else:
			Debug("Input line is missing ts, timestamp, and _write_ts fields: " + input_line, should_debug)
			return

		line_time = datetime.strptime(linestamp, stampformat)
		line_YMD = line_time.strftime("%Y-%m-%d")
		line_hour = line_time.strftime("%H")
		if line_hour == "23":
			line_next_hour = "00"
		elif int(line_hour) < 9:
			line_next_hour = "0" + str(int(line_hour) + 1)
		else:
			line_next_hour = str(int(line_hour) + 1)

		#Following block - could consider using sensor_ipv4 instead of sensor_uuid to have all "sensorname" directories use ipv4 addresses.

		if should_by_sensor and 'bricata' in parsed_line and 'sensor_uuid' in parsed_line['bricata']:
			day_dir = os.path.join(output_directory, parsed_line['bricata']['sensor_uuid'], line_YMD)
		elif should_by_sensor:
			day_dir = os.path.join(output_directory, backup_sensor_name, line_YMD)
		else:
			day_dir = os.path.join(output_directory, line_YMD)
		if not os.path.isdir(day_dir):
			mkdir_p(day_dir)

		log_tail = '.' + line_hour + ':00:00-' + line_next_hour + ':00:00.log'

		#======== Corelight json streaming logs ========
		if '_path' in parsed_line and '_write_ts' in parsed_line:
			if parsed_line['_path'] in known_zeek_filenames:
				if (not should_limit_filenames) or parsed_line['_path'] in limit_writes_to:
					#First, make any needed additions to the main dictionary
					if 'ts' not in parsed_line:
						parsed_line['ts'] = line_time.timestamp()						#This is in the seconds.microseconds from the epoch format used by Zeek logs.

					#write line out to target file
					try:
						with open(os.path.join(day_dir, parsed_line['_path'] + log_tail), "a+") as write_h:	#open for append
							write_h.write(json.dumps(parsed_line) + '\n')					#Check if linefeed needed
					except PermissionError:
						Debug("Unable to append to " + str(os.path.join(day_dir, parsed_line['_path'] + log_tail)), True)
					else:
						save_line_to_log.successful_writes = save_line_to_log.successful_writes + 1
			else:
				Debug('Unknown output filename: ' + str(parsed_line['_path']) + ' , please add to known_zeek_filenames if approved.', True)

		#======== Alert record ========
		elif ('alert' in parsed_line and 'bricata' in parsed_line and 'event_format' in parsed_line['bricata'] and parsed_line['bricata']['event_format'] == 'eve') or ('event_type' in parsed_line and parsed_line['event_type'] == 'alert'):	# pylint: disable=too-many-boolean-expressions
			save_line_to_log.alerts = save_line_to_log.alerts + 1
			if not should_limit_filenames:
				#write line out to "alerts"
				try:
					with open(os.path.join(day_dir, 'alerts' + log_tail), "a+") as write_h:			#open for append
						write_h.write(input_line)
				except PermissionError:
					Debug("Unable to append to " + str(os.path.join(day_dir, 'alerts' + log_tail)), True)

		#======== Unknown format ========
		elif not('bricata' in parsed_line and 'event_format' in parsed_line['bricata'] and parsed_line['bricata']['event_format'] == 'broj' and 'bro_log' in parsed_line and 'event_type' in parsed_line and parsed_line['event_type'] == 'bro_log' and 'file_name' in parsed_line and 'timestamp' in parsed_line):
			Debug("Unknown format for input line, missing one of the required fields: " + input_line, True)

		#======== Unknown output file name ========
		elif not parsed_line['file_name'] in known_zeek_filenames:
			Debug('Unknown output filename: ' + str(parsed_line['file_name']) + ' , please add to known_zeek_filenames if approved.', True)

		#======== Bricata json streaming logs ========
		else:
			if (not should_limit_filenames) or parsed_line['file_name'] in limit_writes_to:
				#First, make any needed additions to the "bro_log" section
				if 'ts' not in parsed_line['bro_log']:
					parsed_line['bro_log']['ts'] = line_time.timestamp()						#This is in the seconds.microseconds from the epoch format used by Zeek logs.

				#write "bro_log" section out to target file
				try:
					with open(os.path.join(day_dir, parsed_line['file_name'] + log_tail), "a+") as write_h:		#open for append
						write_h.write(json.dumps(parsed_line['bro_log']) + '\n')
				except PermissionError:
					Debug("Unable to append to " + str(os.path.join(day_dir, parsed_line['file_name'] + log_tail)), True)
				else:
					save_line_to_log.successful_writes = save_line_to_log.successful_writes + 1



def valid_client(allowed_list, incoming_ip):
	"""Checks if the IP is allowed to connect.  If no list of valid IPs was given on the command line, all IPs can connect."""

	is_valid = False

	if allowed_list:
		if incoming_ip in allowed_list:						#Quick check for exact matches
			is_valid = True
		else:
			for one_valid_ip in allowed_list:				#Slower check just in case user specified upper case or ipv4 without '::ffff:'
				if incoming_ip == one_valid_ip.lower() or '::ffff:' + one_valid_ip == incoming_ip:
					is_valid = True
					break
	else:										#If allowed_list is empty, assume everyone can connect.
		is_valid = True

	return is_valid



def create_server(listening_port, max_connections):
	"""Create the initial listening server socket."""

	try:
		server_h = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)		#We try to open an IPv6 listener (which also accepts IPv4).  If this fails (Gentoo allows a system with no ipv6)...
	except OSError:
		server_h = socket.socket(socket.AF_INET, socket.SOCK_STREAM)		#...we retry with IPv4 only.

	try:
		server_h.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_h.bind(('', int(listening_port)))
		server_h.listen(max_connections)
	except PermissionError:
		fail('Unable to listen on port ' + str(listening_port))
	Debug('Listening on TCP port ' + str(listening_port), True)

	sel_objs.register(server_h, selectors.EVENT_READ, handle_accept)



def handle_accept(sock, event_mask):													# pylint: disable=unused-argument
	"""Callback function called when a new connection is ready to be accept()ed on the server socket."""

	conn_h, client_address = sock.accept()
	if valid_client(user_args['sensorips'], client_address[0]):
		Debug('Accepted connection from: ' + str(client_address), True)

		if user_args['keyfile'] and user_args['certfile']:
			tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
			if cert_passphrase is not None:
				try:
					tls_context.load_cert_chain(user_args['certfile'], user_args['keyfile'], password=cert_passphrase)
				except ssl.SSLError:
					fail("Unable to load certificate and key - invalid passphrase?")
			else:
				tls_context.load_cert_chain(user_args['certfile'], user_args['keyfile'])
			tls_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
			tls_context.set_ciphers('ALL:!COMPLEMENTOFDEFAULT!MEDIUM:!LOW:!eNULL:!aNULL:!AES256-GCM-SHA384:!AES256-SHA256:!AES256-SHA:!CAMELLIA256-SHA:!AES128-GCM-SHA256:!AES128-SHA256:!AES128-SHA:!CAMELLIA128-SHA')
			try:
				ssl_conn_h = tls_context.wrap_socket(conn_h, server_side=True)
			except ssl.SSLError as e:
				fail(e)
			sel_objs.register(ssl_conn_h, selectors.EVENT_READ, handle_read)
		else:
			sel_objs.register(conn_h, selectors.EVENT_READ, handle_read)
	else:
		Debug('Denied connection from: ' + str(client_address), True)
		conn_h.close()



def handle_read(conn_h, event_mask):													# pylint: disable=unused-argument
	"""Save the next complete line from the live TCP connection."""
	#We read (up to) 1024 byte (network_max_read) blocks from
	#the network socket and append them to data_buffer until we
	#have a linefeed in there.  Once we do, we break out the complete
	#line up to the first linefeed, leaving the remainder in
	#data_buffer for future lines.

	if "data_buffers" not in handle_read.__dict__:
		handle_read.data_buffers = {}

	if conn_h not in handle_read.data_buffers:			#Set up an empty buffer that will hold the most recent incomplete line while we wait for the remainder.  Note we need a separate buffer for each connection, so this is a dictionary indexed by the connection handle.
		handle_read.data_buffers[conn_h] = b''

	if "client_hints" not in handle_read.__dict__:
		handle_read.client_hints = {}

	if conn_h not in handle_read.client_hints:
		handle_read.client_hints[conn_h] = 'stream__' + conn_h.getpeername()[0].replace('::ffff:', '').replace('.', '').replace(':', '').lower()		#sensor_name_fallback

	new_data = conn_h.recv(network_max_read)
	if new_data:
		handle_read.data_buffers[conn_h] = handle_read.data_buffers[conn_h] + new_data
		#sys.stderr.write(str(len(new_data)) + "..")
		#sys.stderr.flush()
		while b'\n' in handle_read.data_buffers[conn_h]:
			line_to_process, remainder = handle_read.data_buffers[conn_h].split(b'\n', 1)
			handle_read.data_buffers[conn_h] = remainder
			save_line_to_log(to_str(line_to_process), handle_read.client_hints[conn_h], user_args['outdir'], user_args['debug'], user_args['reprint'], user_args['limit_writes'], user_args['by_sensor'])
	else:
		if handle_read.data_buffers[conn_h]:			#If we have data left over in the buffer, write it before closing.
			save_line_to_log(to_str(handle_read.data_buffers[conn_h]), handle_read.client_hints[conn_h], user_args['outdir'], user_args['debug'], user_args['reprint'], user_args['limit_writes'], user_args['by_sensor'])		#Write out last incomplete line
		del handle_read.data_buffers[conn_h]
		del handle_read.client_hints[conn_h]
		sel_objs.unregister(conn_h)
		conn_h.close()
		Debug('Connection closed.', True)



#Reference list at https://docs.zeek.org/en/current/script-reference/log-files.html
known_zeek_filenames = ('barnyard2', 'broker', 'capture_loss', 'cluster', 'config', 'conn', 'corelight_overall_capture_loss', 'dce_rpc', 'dhcp', 'dnp3', 'dns', 'dpd', 'files', 'ftp', 'http', 'intel', 'irc', 'kerberos', 'known_certs', 'known_hosts', 'known_modbus', 'known_services', 'loaded_scripts', 'modbus', 'modbus_register_change', 'mysql', 'netcontrol', 'netcontrol_drop', 'netcontrol_shunt', 'netcontrol_catch_release', 'notice', 'notice_alarm', 'ntlm', 'ntp', 'observed_users', 'ocsp', 'openflow', 'packet_filter', 'pe', 'print', 'prof', 'radius', 'rdp', 'reporter', 'rfb', 'signatures', 'sip', 'smb_cmd', 'smb_files', 'smb_mapping', 'smtp', 'snmp', 'socks', 'software', 'ssh', 'ssl', 'stats', 'stderr', 'stdout', 'suricata_corelight', 'suricata_stats', 'syslog', 'traceroute', 'tunnel', 'unified2', 'unknown_protocols', 'weird', 'weird_stats', 'x509')
limit_writes_to = ('conn', 'dns', 'http', 'ssl', 'x509', 'known_certs')
input_filenames = []
save_json_stream_version = '0.5.3'
default_output_directory = './zeeklogs/'
network_max_read = 1024
default_max_connections = 778						#Each corelight sensor appears to take a maximum of 12 connections, each Bricata takes 1.  Bash appears to have a max of 1024 without additional ulimit tweaking.


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='save_json_stream, version ' + str(save_json_stream_version))
	parser.add_argument('-f', '--files', help='Input file(s) to process - will process stdin if none', required=False, default=[], nargs='*')
	parser.add_argument('-p', '--port', help='TCP port to listen on (overrides stdin and and --files options)', required=False, default=None)
	parser.add_argument('-o', '--outdir', help='Destination directory name (default is ' + str(default_output_directory) + ')', required=False, default=default_output_directory)
	parser.add_argument('-d', '--debug', help='Show additional debugging on stderr', required=False, default=False, action='store_true')
	parser.add_argument('-c', '--certfile', help='SSL certificate file full path', required=False, default=None)
	parser.add_argument('-k', '--keyfile', help='SSL key file full path', required=False, default=None)
	parser.add_argument('--passphrase_file', help='Full path to file containing passphrase', required=False, default=None)
	parser.add_argument('--passphrase_ask', help='Interactively ask for the passphrase at startup', required=False, default=False, action='store_true')
	parser.add_argument('-s', '--sensorips', help='Sensors that are allowed to connect', required=False, default=[], nargs='*')
	parser.add_argument('--reprint', help='Copy all valid json lines to stdout', required=False, default=False, action='store_true')
	parser.add_argument('--limit_writes', help='Only write out the 6 file types used by Rita and AC-Hunter', required=False, default=False, action='store_true')
	parser.add_argument('--by_sensor', help='Group logs under a sensor UUID directory (outdir/sensor_uuid/YYYY-MM-DD/)', required=False, default=False, action='store_true')
	user_args = vars(parser.parse_args())

	#Check for valid argument combinations
	if user_args['files'] and user_args['port']:
		fail('Cannot simultaneously read from a file and a TCP port, please pick one or the other.')

	if (user_args['certfile'] and not user_args['keyfile']) or (not user_args['certfile'] and user_args['keyfile']):
		fail('To make an TLS socket you need both a key and a certificate')
	elif user_args['certfile'] and user_args['keyfile'] and not user_args['port']:
		fail('To have a TLS-wrapped socket you first need a listening port.')

	max_listeners = default_max_connections

	cert_passphrase = None
	if user_args['passphrase_file'] and os.path.exists(user_args['passphrase_file']) and os.access(user_args['passphrase_file'], os.R_OK):
		with open(user_args['passphrase_file']) as certpass_h:
			cert_passphrase = certpass_h.read().rstrip('\n')
	elif user_args['passphrase_ask']:
		cert_passphrase = getpass.getpass(prompt="Please enter the TLS key passhrase (will not show up on the screen): ").rstrip('\n')		#Asks for the password without echoing it to the screen
	elif user_args['passphrase_file']:
		Debug('Unable to read ' + user_args['passphrase_file'], True)

	mkdir_p(user_args['outdir'])
	if not os.path.exists(user_args['outdir']) or not os.access(user_args['outdir'], os.W_OK):
		fail('Unable to create or write to output directory ' + user_args['outdir'])

	for one_file in user_args['files']:
		if os.path.exists(one_file) and os.access(one_file, os.R_OK):
			input_filenames.append(one_file)
		else:
			sys.stderr.write('Unable to locate or read ' + one_file + ' , skipping this file.\n')
			sys.stderr.flush()

	if user_args['port']:							#If user requested a port, we won't look at files or stdin.
		sel_objs = selectors.DefaultSelector()				#The main listening socket and all connections are in here - we select() for new connections and new lines.

		create_server(user_args['port'], max_listeners)

		continue_listening = True
		while continue_listening:							#No current way to shut it down
			try:
				for key, mask in sel_objs.select(timeout=1):		#Wait for either new connection or data on existing handle...
					callback = key.data
					callback(key.fileobj, mask)			#...and hand it off the the appropriate handler.
			except KeyboardInterrupt:
				Debug('Shutting down.', user_args['debug'])
				continue_listening = False

		sel_objs.close()

	else:									#Process input files, or stdin if none (both handled by the fileinput module)..
		try:
			for one_line in fileinput.input(input_filenames):
				save_line_to_log(to_str(one_line), 'fileimport', user_args['outdir'], user_args['debug'], user_args['reprint'], user_args['limit_writes'], user_args['by_sensor'])
		except KeyboardInterrupt:
			pass

	if user_args['debug']:
		if "input_lines" in save_line_to_log.__dict__:
			Debug(str(save_line_to_log.input_lines) + " lines read", user_args['debug'])
		if "successful_writes" in save_line_to_log.__dict__:
			Debug(str(save_line_to_log.successful_writes) + " lines successfully written", user_args['debug'])
		if "alerts" in save_line_to_log.__dict__:
			Debug(str(save_line_to_log.alerts) + " alerts", user_args['debug'])
