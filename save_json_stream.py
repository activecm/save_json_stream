#!/usr/bin/env python3
"""Reads lines from command-line-supplied filenames (or stdin if none) and saves them out to the appropriate zeek log file."""
#Tested under python3.  (Note, python 2 will not successfully parse the date string because of the time zone field at the end.)
#Copyright 2021, William Stearns <bill@activecountermeasures.com>
#Released under the GPL

import errno
import fileinput	#Allows one to read from files specified on the command line or read directly from stdin automatically
import argparse
import os
import socket
import sys
import json
import ssl
from datetime import datetime


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


def save_line_to_log(input_line, backup_sensor_name, output_directory, should_debug, should_reprint, should_limit_filenames, should_by_sensor):	# pylint: disable=too-many-arguments,too-many-branches,too-many-statements
	"""Take the single input line and save it to the appropriate log file under the output_directory."""
	#Input line is a string, not bytes.

	if "successful_writes" not in save_line_to_log.__dict__:
		save_line_to_log.successful_writes = 0
	if "alerts" not in save_line_to_log.__dict__:
		save_line_to_log.alerts = 0

	try:
		parsed_line = json.loads(input_line)		#Returns a nested python dictionary
	except json.decoder.JSONDecodeError:
		Debug("json parse error in: " + input_line, should_debug)
	else:
		if should_reprint:
			print(input_line, end='')

		if not 'timestamp' in parsed_line:
			Debug("Input line is missing timestamp field: " + input_line, should_debug)
			return

		line_time = datetime.strptime(parsed_line['timestamp'], "%Y-%m-%dT%H:%M:%S.%f%z")
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

		if '_path' in parsed_line and '_write_ts' in parsed_line:
			#Corelight json streaming logs
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

		elif 'alert' in parsed_line and 'bricata' in parsed_line and 'event_format' in parsed_line['bricata'] and parsed_line['bricata']['event_format'] == 'eve':
			#Suricata Eve alerts
			save_line_to_log.alerts = save_line_to_log.alerts + 1
			if not should_limit_filenames:
				#write line out to "eve_alerts"
				try:
					with open(os.path.join(day_dir, 'eve_alerts' + log_tail), "a+") as write_h:			#open for append
						write_h.write(input_line)
				except PermissionError:
					Debug("Unable to append to " + str(os.path.join(day_dir, 'eve_alerts' + log_tail)), True)

		elif not('bricata' in parsed_line and 'event_format' in parsed_line['bricata'] and parsed_line['bricata']['event_format'] == 'broj' and 'bro_log' in parsed_line and 'event_type' in parsed_line and parsed_line['event_type'] == 'bro_log' and 'file_name' in parsed_line and 'timestamp' in parsed_line):
			Debug("Unknown format for input line, missing one of the required fields: " + input_line, True)

		elif not parsed_line['file_name'] in known_zeek_filenames:
			Debug('Unknown output filename: ' + str(parsed_line['file_name']) + ' , please add to known_zeek_filenames if approved.', True)

		else:
			#Format is good
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
	"""Checks if the IP is allowed to connect."""

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


def get_connection_handle(listening_port, keyfile, certfile, allowed_ips, should_debug):
	"""Open a TCP listening socket.  The port value is used on first entry, and ignored from then on."""

	client_hint = ''

	#We're making a listening socket on that port _that persists over calls to this function_.
	if "sock_h" not in get_connection_handle.__dict__:
		get_connection_handle.sock_h = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
		try:
			get_connection_handle.sock_h.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			get_connection_handle.sock_h.bind(('', int(listening_port)))
			get_connection_handle.sock_h.listen(1)
		except PermissionError:
			fail('Unable to listen on port ' + str(listening_port))
		Debug('Listening on TCP port ' + str(listening_port), True)

	if "tls_context" not in get_connection_handle.__dict__:
		if keyfile and certfile:
			get_connection_handle.tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
			get_connection_handle.tls_context.load_cert_chain(certfile, keyfile)
			get_connection_handle.tls_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
			get_connection_handle.tls_context.set_ciphers('ALL:!COMPLEMENTOFDEFAULT!MEDIUM:!LOW:!eNULL:!aNULL:!AES256-GCM-SHA384:!AES256-SHA256:!AES256-SHA:!CAMELLIA256-SHA:!AES128-GCM-SHA256:!AES128-SHA256:!AES128-SHA:!CAMELLIA128-SHA')
		else:
			get_connection_handle.tls_context = None

	try:
		Debug('Waiting for an incoming connection.', should_debug)
		conn_h, client_address = get_connection_handle.sock_h.accept()
		while not valid_client(allowed_ips, client_address[0]):
			Debug('Denied connection from: ' + str(client_address), True)
			conn_h.close()
			conn_h, client_address = get_connection_handle.sock_h.accept()

		Debug('Accepted connection from: ' + str(client_address), True)
		client_hint = client_address[0].replace('::ffff:', '').replace('.', '').replace(':', '').lower()
	except KeyboardInterrupt:
		Debug("Exiting.", should_debug)
		sys.exit(0)

	if get_connection_handle.tls_context:
		try:
			ssl_conn_h = get_connection_handle.tls_context.wrap_socket(conn_h, server_side=True)
			return ssl_conn_h, client_hint
		except ssl.SSLError as e:
			fail(e)
	else:
		return conn_h, client_hint


def next_tcp_line(conn_h):
	"""Return the next complete line from the live TCP connection.  Keep reading until we have a complete line."""
	#We keep reading (up to) 128 byte blocks from the network socket and appending them to data_buffer until we have a linefeed in there.
	#Once we do, we break out the complete line up to the first linefeed, leaving the remainder in data_buffer for future lines.

	line_to_process = b''

	if "data_buffer" not in next_tcp_line.__dict__:
		next_tcp_line.data_buffer = b''

	end_of_connection = False
	while not end_of_connection and (b'\n' not in next_tcp_line.data_buffer):
		new_data = conn_h.recv(network_max_read)
		if new_data:
			next_tcp_line.data_buffer = next_tcp_line.data_buffer + new_data
			#sys.stderr.write(str(len(new_data)) + "..")
			#sys.stderr.flush()
		else:
			end_of_connection = True

	if b'\n' in next_tcp_line.data_buffer:
		line_to_process, remainder = next_tcp_line.data_buffer.split(b'\n', 1)
		next_tcp_line.data_buffer = remainder
		#sys.stderr.write('\n')
		#sys.stderr.flush()

	if end_of_connection:
		conn_h.close()
		conn_h = None

	return line_to_process, end_of_connection


known_zeek_filenames = ('conn', 'dce_rpc', 'dns', 'dpd', 'files', 'ftp', 'http', 'kerberos', 'known_certs', 'notice', 'observed_users', 'pe', 'ssh', 'ssl', 'weird', 'x509')
limit_writes_to = ('conn', 'dns', 'http', 'ssl', 'x509', 'known_certs')
InputFilenames = []
save_json_stream_version = '0.4.3'
default_output_directory = './zeeklogs/'
network_max_read = 128


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='save_json_stream, version ' + str(save_json_stream_version))
	parser.add_argument('-f', '--files', help='Input file(s) to process - will process stdin if none', required=False, default=[], nargs='*')
	parser.add_argument('-p', '--port', help='TCP port to listen on (overrides stdin and and --files options)', required=False, default=None)
	parser.add_argument('-o', '--outdir', help='Destination directory name (default is ' + str(default_output_directory) + ')', required=False, default=default_output_directory)
	parser.add_argument('-d', '--debug', help='Show additional debugging on stderr', required=False, default=False, action='store_true')
	parser.add_argument('-c', '--certfile', help='SSL certificate file full path', required=False, default=None)
	parser.add_argument('-k', '--keyfile', help='SSL key file full path', required=False, default=None)
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

	mkdir_p(user_args['outdir'])
	if not os.path.exists(user_args['outdir']) or not os.access(user_args['outdir'], os.W_OK):
		sys.stderr.write('Unable to create or write to output directory ' + user_args['outdir'] + ' , exiting.\n')
		sys.stderr.flush()
		sys.exit()

	for one_file in user_args['files']:
		if os.path.exists(one_file) and os.access(one_file, os.R_OK):
			InputFilenames.append(one_file)
		else:
			sys.stderr.write('Unable to locate or read ' + one_file + ' , skipping this file.\n')
			sys.stderr.flush()

	input_lines = 0
	if user_args['port']:							#If user requested a port, we won't look at files or stdin.
		while True:
			connection_h, ip_hint = get_connection_handle(user_args['port'], user_args['keyfile'], user_args['certfile'], user_args['sensorips'], user_args['debug'])	#ip_hint is the ipv4 or ipv6 address without periods or colons
			sensor_name_fallback = 'stream__' + ip_hint
			connection_closed = False
			while not connection_closed:
				try:
					one_line, connection_closed = next_tcp_line(connection_h)
					if one_line:
						input_lines = input_lines + 1
						save_line_to_log(to_str(one_line), sensor_name_fallback, user_args['outdir'], user_args['debug'], user_args['reprint'], user_args['limit_writes'], user_args['by_sensor'])
				except KeyboardInterrupt:
					pass
	else:									#Process input files, or stdin if none (both handled by the fileinput module)..
		try:
			for one_line in fileinput.input(InputFilenames):
				input_lines = input_lines + 1
				save_line_to_log(to_str(one_line), sensor_name_fallback, user_args['outdir'], user_args['debug'], user_args['reprint'], user_args['limit_writes'], user_args['by_sensor'])
		except KeyboardInterrupt:
			pass

	if user_args['debug']:
		Debug(str(input_lines) + " lines read", user_args['debug'])
		if "successful_writes" in save_line_to_log.__dict__:
			Debug(str(save_line_to_log.successful_writes) + " lines successfully written", user_args['debug'])
		if "alerts" in save_line_to_log.__dict__:
			Debug(str(save_line_to_log.alerts) + " alerts", user_args['debug'])
