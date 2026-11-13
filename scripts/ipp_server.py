#!/usr/bin/env python3

from ippserver.server import IPPServer
import ippserver.behaviour as behaviour
from ippserver.server import IPPRequestHandler
from ippserver.constants import (
    OperationEnum, SectionEnum, TagEnum
)
from ippserver.parsers import Integer, Enum, Boolean
class LabPrinter(behaviour.StatelessPrinter):

    def __init__(self):
        super(LabPrinter, self).__init__()

    @property
    def printer_uri(self):
        return b'ipp://172.18.0.1:8631/printers/NAME'

    @property
    def base_uri(self):
        return b'ipp://172.18.0.1:8631/'

    def printer_list_attributes(self):

        attr = {
            (
                SectionEnum.printer,
                b'printer-uri-supported',
                TagEnum.uri
            ): [self.printer_uri],

            (
                SectionEnum.printer,
                b'uri-authentication-supported',
                TagEnum.keyword
            ): [b'none'],

            (
                SectionEnum.printer,
                b'uri-security-supported',
                TagEnum.keyword
            ): [b'none'],

            (
                SectionEnum.printer,
                b'printer-name',
                TagEnum.name_without_language
            ): [b'LabPrinter'],

            (
                SectionEnum.printer,
                b'printer-info',
                TagEnum.text_without_language
            ): [b'Benign virtual IPP printer'],
            (
                SectionEnum.printer,
                b'printer-make-and-model',
                TagEnum.text_without_language
            ): [b'Virtual IPP Printer'],

            (
                SectionEnum.printer,
                b'printer-state',
                TagEnum.enum
            ): [Enum(3).bytes()],

            (
                SectionEnum.printer,
                b'printer-state-reasons',
                TagEnum.keyword
            ): [b'none'],

            (
                SectionEnum.printer,
                b'ipp-versions-supported',
                TagEnum.keyword
            ): [b'1.1'],

            (
                SectionEnum.printer,
                b'operations-supported',
                TagEnum.enum
            ): [              Enum(x).bytes()
                for x in (
                    OperationEnum.print_job,
                    OperationEnum.validate_job,
                    OperationEnum.cancel_job,
                    OperationEnum.get_job_attributes,
                    OperationEnum.get_printer_attributes,
                )
            ],

            (
                SectionEnum.printer,
                b'multiple-document-jobs-supported',
                TagEnum.boolean
            ): [Boolean(False).bytes()],

            (
                SectionEnum.printer,
                b'charset-configured',
                TagEnum.charset
            ): [b'utf-8'],

            (
                SectionEnum.printer,
                b'charset-supported',
                TagEnum.charset
            ): [b'utf-8'],

            (
                SectionEnum.printer,
                b'natural-language-configured',
                TagEnum.natural_language
            ): [b'en'],

            (
                SectionEnum.printer,
                b'generated-natural-language-supported',
                TagEnum.natural_language
            ): [b'en'],

            (
                SectionEnum.printer,
                b'document-format-default',
                TagEnum.mime_media_type
            ): [b'application/pdf'],

            (
                SectionEnum.printer,
                b'document-format-supported',
                TagEnum.mime_media_type
            ): [b'application/pdf'],

            (
                SectionEnum.printer,
                b'printer-is-accepting-jobs',
                TagEnum.boolean
            ): [Boolean(True).bytes()],

            (
                SectionEnum.printer,
                b'queued-job-count',
                TagEnum.integer
            ): [Integer(0).bytes()],

            (
                SectionEnum.printer,
                b'pdl-override-supported',
                TagEnum.keyword
            ): [b'not-attempted'],

            (
                SectionEnum.printer,
                b'printer-up-time',
                TagEnum.integer
            ): [Integer(self.printer_uptime()).bytes()],

            (
                SectionEnum.printer,
                b'compression-supported',
                TagEnum.keyword
            ): [b'none'],

            (
                SectionEnum.printer,
                b'printer-location',
                TagEnum.text_without_language
            ): [b'Kali Linux'],

            (
                SectionEnum.printer,
                b'printer-more-info',
                TagEnum.uri
            ): [b'https://www.example.com/'],
        }

        attr.update(super().minimal_attributes())
        return attr


if __name__ == "__main__":

    SERVER_HOST = "0.0.0.0"
    SERVER_PORT = 8631

    server = IPPServer(
        (SERVER_HOST, SERVER_PORT),
        IPPRequestHandler,
        LabPrinter()
    )

    print(
        "Lab IPP printer listening on %s:%d"
        % (SERVER_HOST, SERVER_PORT)
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping IPP server...")
        server.server_close()
