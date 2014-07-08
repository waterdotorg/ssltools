#!/usr/bin/env python
# -*- coding: utf-8 -*-

import settings
import smtplib
import socket
import ssl
import ssltools


def main():
    error_list = []
    warning_list = []
    success_list = []

    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs()

    for domain in settings.DOMAINS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            """
            ssl_sock = ssl.wrap_socket(
                s,
                ca_certs="/etc/ssl/certs/ca-certificates.crt",
                cert_reqs=ssl.CERT_REQUIRED,
            )
            """
            ssl_sock = context.wrap_socket(s, server_hostname=domain)
            ssl_sock.connect((domain, 443))
            cert = ssl_sock.getpeercert()
            if not cert:
                raise Exception('No cert returned')
            # ssltools.match_hostname(cert, domain)
            ssl.match_hostname(cert, domain)
            days = ssltools.check_expiration(cert)
            if days <= settings.WARNING_DAYS:
                warning_list.append(
                    {'domain': domain, 'msg': '%d days to expiration' % days}
                )
            else:
                success_list.append(
                    {'domain': domain, 'msg': '%d days to expiration' % days}
                )
        except Exception as e:
            error_list.append({'domain': domain, 'msg': e})
        finally:
            ssl_sock.close()

    # Send Mail
    msg = 'Subject: SSL Cert Check\n\n'
    msg += 'Error\n=======\n'
    for error in error_list:
        msg += '%s: %s\n' % (error.get('domain'), error.get('msg'))

    msg += '\n\nWarning\n========\n'
    for warning in warning_list:
        msg += '%s: %s\n' % (warning.get('domain'), warning.get('msg'))

    msg += '\n\nSuccess\n========\n'
    for success in success_list:
        msg += '%s: %s\n' % (success.get('domain'), success.get('msg'))

    s = smtplib.SMTP('localhost')
    s.sendmail(
        settings.FROM_EMAIL,
        [settings.TO_EMAIL],
        msg,
    )
    s.quit()

if __name__ == "__main__":
    main()
