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
import json
import base64
import binascii
from src.utils import menu
from src.utils import settings
from src.thirdparty.odict import OrderedDict
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.flatten_json.flatten_json import unflatten_list

"""
Extract a single header's value from a raw "Name: value" line, or None if it's a different header.
"""
def _extract_header_value(header_name, line):
  match = re.findall(r"^" + header_name + ":" + " (.*)", line)
  return "".join([str(i) for i in match]) if match else None

"""
Parse target and data from http proxy logs (i.e Burp or WebScarab)
"""
def logfile_parser():
  """
  Warning message for mutiple request in same log file.
  """
  def multi_requests():
    err_msg = "This tool does not support multiple"
    if menu.options.requestfile:
      err_msg += " requests"
    elif menu.options.logfile:
      err_msg += " targets"
    err_msg += ", so it will ignore all coming"
    if menu.options.requestfile:
      err_msg += " requests"
    elif menu.options.logfile:
      err_msg += " targets"
    err_msg += "."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    
    return False

  """
  Error message for invalid data.
  """
  def invalid_data(request):
    err_msg = "Specified file "
    err_msg += "'" + os.path.split(request_file)[1] + "'"
    err_msg += " does not contain a valid HTTP request."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if menu.options.requestfile:
    info_msg = "Parsing HTTP request "
    request_file = menu.options.requestfile
    
  elif menu.options.logfile:
    info_msg = "Parsing target "
    request_file = menu.options.logfile

  if not os.path.exists(request_file):
    err_msg = "It seems the '" + request_file + "' file does not exist."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    if os.stat(request_file).st_size != 0:
      with open(request_file, encoding=settings.DEFAULT_CODEC) as file:
        request = file.read()
      # Normalize CRLF line endings.
      request = request.replace(settings.END_LINE.CRLF, settings.END_LINE.LF)
    else:
      invalid_data(request_file)

    if menu.options.requestfile or menu.options.logfile:
      c = 1
      request_headers = []
      if menu.options.header:
        request_headers.append(menu.options.header)
      elif menu.options.headers:
        request_headers.extend(menu.options.headers.split(settings.END_LINE.ESCAPED_LF))
      request_lines = request.split(settings.END_LINE.LF)
      while c < len(request_lines) and len(request_lines[c]) > 0 and ':' in request_lines[c]:
        x = request_lines[c].find(':')
        header_name = request_lines[c][:x].title()
        header_value = request_lines[c][x + 1:]
        request_headers.append(header_name + ":" + header_value)
        c += 1
      if c < len(request_lines) and len(request_lines[c]) == 0:
        c += 1
      menu.options.data = "".join(request_lines[c:] if c < len(request_lines) else "")

      # Normalize a JSON body right away, so every request (including the first
      # connectivity check) uses the same pretty-printed form, not the raw file layout.
      if re.search(settings.JSON_RECOGNITION_REGEX, menu.options.data) or re.search(settings.JSON_LIKE_RECOGNITION_REGEX, menu.options.data):
        try:
          parsed = json.loads(menu.options.data, object_pairs_hook=OrderedDict)
          menu.options.data = json.dumps(unflatten_list(parsed), indent=2, ensure_ascii=False)
        except Exception:
          pass
      settings.RAW_HTTP_HEADERS = settings.END_LINE.ESCAPED_LF.join(request_headers)

  except IOError as err_msg:
    error_msg = "The '" + request_file + "' "
    error_msg += str(err_msg.args[1]).lower() + "."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit()

  pattern = r'HTTP/([\d.]+)'
  if len(re.findall(pattern, request)) > 1:
    multi_requests()

  # Safely determine HTTP method
  if len(settings.HTTP_METHOD) == 0:
    lines = request.strip().splitlines()
    if lines and len(lines[0].split()) >= 1:
      http_method = lines[0].split()[0]
    else:
      # fallback to default method if malformed/empty
      http_method = settings.HTTPMETHOD.GET
    settings.HTTP_METHOD = http_method
  else:
    http_method = settings.HTTP_METHOD

  # Safely extract request URL
  match = re.search(r"\s(.*?)\sHTTP/", request or "")
  request_url = match.group(1) if match else ""

  if not request_url:
    invalid_data(request_file)

  request_url = "".join([str(i) for i in request_url])
  # Check for other headers
  extra_headers = ""
  scheme = "http://"

  for line in request_headers:
    host_value = _extract_header_value(settings.HOST, line)
    if host_value is not None:
      menu.options.host = host_value
    agent_value = _extract_header_value(settings.USER_AGENT, line)
    if agent_value is not None:
      menu.options.agent = agent_value
    cookie_value = _extract_header_value(settings.COOKIE, line)
    if cookie_value is not None:
      menu.options.cookie = cookie_value
    referer_value = _extract_header_value(settings.REFERER, line)
    if referer_value is not None:
      menu.options.referer = referer_value
      if "https://" in referer_value:
        scheme = "https://"
    if re.findall(r"" + settings.AUTHORIZATION + ":" + " (.*)", line):
      auth_provided = "".join([str(i) for i in re.findall(r"" + settings.AUTHORIZATION + ":" + " (.*)", line)]).split()
      if auth_provided:
        menu.options.auth_type = auth_provided[0].lower()
        if menu.options.auth_type.lower() == settings.AUTH_TYPE.BASIC:
          try:
            # Add base64 padding if missing
            b64_string = auth_provided[1]
            b64_string += '=' * (-len(b64_string) % 4)
            menu.options.auth_cred = base64.b64decode(b64_string).decode()
          except (binascii.Error, UnicodeDecodeError) as e:
            err_msg = "Invalid base64-encoded credentials provided in Authorization header: " + format(str(e))
            settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
            raise SystemExit()

        elif menu.options.auth_type.lower() == settings.AUTH_TYPE.DIGEST:
          if not menu.options.auth_cred:
            err_msg = "Use the '--auth-cred' option to provide a valid pair of "
            err_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\") "
            settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
            raise SystemExit()

    # Add extra headers
    else:
      match = re.match(r"(.*): (.*)", line)
      # Ignore some headers.
      if match and match.group(1) not in (settings.CONTENT_LENGTH, settings.ACCEPT_ENCODING):
        extra_headers += match.group(1) + ":" + match.group(2) + settings.END_LINE.ESCAPED_LF

  # Extra headers
  menu.options.headers = extra_headers
  
  # Target URL
  if not menu.options.host:
    invalid_data(request_file)
  else:
    if len(_urllib.parse.urlparse(request_url).scheme) == 0:
      request_url = scheme + request_url
    if not menu.options.host in request_url:
      request_url = request_url.replace(scheme, scheme + menu.options.host)
    request_url = checks.check_http_s(request_url)
    info_msg += "using the '" + os.path.split(request_file)[1] + "' file. "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    
    menu.options.url = request_url

# eof