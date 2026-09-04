#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""
import os
import re
import sys
import shlex
import tempfile
from datetime import date
from datetime import datetime
from src.utils import menu
from src.utils import common
from src.utils import settings
from src.utils import session_handler
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib

"""
1. Generate injection logs (logs.txt) in "./ouput" file.
2. Check for logs updates and apply if any!
"""

"""
Directory creation
"""
def path_creation(path):
  if not os.path.exists(path):
    try:
      os.mkdir(path)
    except OSError as err_msg:
      try:
        error_msg = str(err_msg).split("] ")[1] + "."
      except IndexError:
        error_msg = str(err_msg) + "."
      settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
      raise SystemExit()

"""
Logs filename creation.
"""
def logs_filename_creation(url):
  output_dir = menu.options.output_dir

  if output_dir:
    output_dir = os.path.abspath(output_dir)
    if os.path.isdir(output_dir):
      info_msg = "Using output directory '" + output_dir + "'."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    else:
      try:
        os.makedirs(output_dir, exist_ok=True)
        info_msg = "Created missing output directory '" + output_dir + "'."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      except OSError:
        error_msg = "Unable to create missing output directory '" + output_dir + "'."
        settings.print_data_to_stdout(settings.print_error_msg(error_msg))
        try:
          output_dir = tempfile.mkdtemp(prefix=settings.APPLICATION)
          warn_msg = "Using temporary output directory '" + output_dir + "' instead."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
        except (OSError, RuntimeError):
          common.unhandled_exception()
  else:
    output_dir = settings.OUTPUT_DIR
    path_creation(os.path.dirname(output_dir))

  # Ensure path ends with OS-specific separator
  output_dir = os.path.join(output_dir, '')

  # Create the logs filename
  return create_log_file(url, output_dir)

"""
Create log files
"""
def create_log_file(url, output_dir):
  host = _urllib.parse.urlparse(url).netloc.replace(":","_") + "/"
  logs_path = output_dir + host

  path_creation(logs_path)

  # Create cli history file if does not exist.
  settings.CLI_HISTORY = logs_path + "cli_history"
  if not os.path.exists(settings.CLI_HISTORY):
    open(settings.CLI_HISTORY,'a').close()

  if menu.options.session_file is not None:
    if os.path.exists(menu.options.session_file):
      settings.SESSION_FILE = menu.options.session_file
    else:
      err_msg = "The provided session file ('" + menu.options.session_file + "') does not exist."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
  else:
    settings.SESSION_FILE = logs_path + "session.db"

  if os.path.exists(settings.CLI_HISTORY):
    checks.load_cmd_history()

  # The logs filename construction.
  filename = logs_path + settings.OUTPUT_FILE
  try:
    with open(filename, 'w' if menu.options.flush_session else 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        http_request_method = settings.HTTPMETHOD.POST if menu.options.data else settings.HTTPMETHOD.GET
        output_file.write("Target: " + url + " (" + http_request_method + ")" + settings.END_LINE.LF)
        output_file.write("Command: " + " ".join(shlex.quote(_) for _ in sys.argv) + settings.END_LINE.LF)
        output_file.write("Started: " + str(date.today()) + settings.SINGLE_WHITESPACE + datetime.now().strftime("%H:%M:%S") + settings.END_LINE.LF)
  except IOError as err_msg:
    try:
      error_msg = str(err_msg.args[0]).split("] ")[1] + "."
    except:
      error_msg = str(err_msg.args[0]) + "."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit()

  if not menu.options.output_dir:
    filename = os.path.abspath(filename)
    
  return filename

"""
Append a line to the report - a blank line separates it from a differently grouped one.
"""
def add_line(filename, text, group=""):
  if menu.options.no_logging:
    return
  try:
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if group != settings.LAST_LOG_GROUP:
        output_file.write(settings.END_LINE.LF)
        settings.LAST_LOG_GROUP = group
      output_file.write(text + settings.END_LINE.LF)
  except:
    pass

"""
Add a confirmed finding in log files, in the same format the console summary prints it.
"""
def add_finding(filename, injection_type, technique, http_request_method, vuln_parameter, payload, title=None):
  settings.SHOW_LOGS_MSG = True
  if not settings.LOGGED_FINDINGS_HEADER:
    add_line(filename, settings.APPLICATION + " identified the following injection point(s):", group="findings")
    settings.LOGGED_FINDINGS_HEADER = True
  parameter = (vuln_parameter, http_request_method)
  if parameter != settings.LAST_LOGGED_PARAMETER:
    add_line(filename, checks.finding_parameter_line(vuln_parameter, http_request_method), group="findings")
    settings.LAST_LOGGED_PARAMETER = parameter
  else:
    add_line(filename, "", group="findings")
  payload = str(checks.url_decode(payload)).replace(settings.END_LINE.LF, settings.END_LINE.ESCAPED_LF)
  for line in checks.finding_summary_lines(technique, injection_type, payload, title):
    add_line(filename, settings.strip_ansi_codes(line), group="findings")

"""
Add any executed command and
execution output result in log files.
"""
def executed_command(filename, cmd, output):
  add_line(filename, "Executed command: " + cmd, group="command:" + cmd)
  add_line(filename, str(output.encode(settings.DEFAULT_CODEC).decode()), group="command:" + cmd)

"""
Fetched data logged to text files.
"""
def logs_notification(filename):
  # Save command history.
  if not menu.options.no_logging:
    info_msg = "Fetched data logged to text files under '" + filename + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Log all HTTP traffic into a textual file.
"""
def log_traffic(header):
  try:
    with open(menu.options.traffic_file, "a", encoding=settings.DEFAULT_CODEC) as output_file:
      output_file.write(header)
  except:
    pass

"""
Close the report with the run's totals - only if something was actually logged.
"""
def add_footer(filename):
  if menu.options.no_logging or not settings.LOGGED_FINDINGS_HEADER:
    return
  add_line(filename, "Finished: " + str(date.today()) + settings.SINGLE_WHITESPACE + datetime.now().strftime("%H:%M:%S") +
                     "   Requests: " + str(settings.TOTAL_OF_REQUESTS) +
                     "   Target OS: " + settings.TARGET_OS.title(), group="footer")

"""
Print logs notification.
"""
def print_logs_notification(filename, url):
  if os.path.exists(settings.CLI_HISTORY):
    checks.save_cmd_history()
  add_footer(filename)
  if settings.SHOW_LOGS_MSG == True and not menu.options.no_logging:
    if not settings.LOAD_SESSION:
      logs_notification(filename)
  if url:
    session_handler.clear(url)

# eof