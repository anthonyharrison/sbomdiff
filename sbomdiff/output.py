# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

""" Set up Output Formatting """


class OutputManager:
    """Helper class for managing output to file and console."""

    def __init__(self, out_type="file", filename=None):
        self.out_type = out_type
        self.filename = filename
        if self.out_type == "file":
            self.file_handle = open(filename, "w")
        else:
            self.file_handle = None

    def close(self):
        # print("close...")
        if self.out_type == "file":
            self.file_handle.close()

    def file_out(self, message):
        self.file_handle.write(message + "\n")

    def console_out(self, message):
        print(message)

    def show(self, message):
        if self.out_type == "file":
            self.file_out(message)
        else:
            self.console_out(message)


class SBOMOutput:
    """Output manager """

    def __init__(self, filename="console"):
        self.filename = filename
        self.type = "console"
        if self.filename != "":
            self.type = "file"
        self.output_manager = OutputManager(self.type, self.filename)

    def send_output(self, data):
        self.output_manager.show(data)

    def close_output(self):
        self.output_manager.close()
