from typing import Optional, Dict, Any

from scrapli.transport.transport import Transport
from scrapli.exceptions import ScrapliAuthenticationFailed

SERIAL_TRANSPORT_ARGS = (
        "device",
        "auth_username",
        "auth_password",)


class SerialTransport(Transport):

    from serial import Serial

    def __init__(
        self,
        auth_username: str = "",
        auth_password: str = "",
        auth_bypass: bool = False,
        timeout_socket: int = 5,
        timeout_transport: int = 5,
        timeout_ops: int = 10,
        timeout_exit: bool = True,
        keepalive: bool = False,
        keepalive_interval: int = 30,
        keepalive_type: str = "",
        keepalive_pattern: str = "\005",
        comms_prompt_pattern: str = r"^[a-z0-9.\-@()/:]{1,32}[#>$]$",
        comms_return_char: str = "\n",
        comms_ansi: bool = False,
        transport_options: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> None:
        r"""
        TelnetTransport Object

        Inherit from Transport ABC
        TelnetTransport <- Transport (ABC)

        Note that comms_prompt_pattern, comms_return_char and comms_ansi are only passed here to
        handle "in channel" authentication required by SystemSSH -- these are assigned to private
        attributes in this class and ignored after authentication. If you wish to modify these
        values on a "live" scrapli connection, modify them in the Channel object, i.e.
        `conn.channel.comms_prompt_pattern`. Additionally timeout_ops is passed and assigned to
        _timeout_ops to use the same timeout_ops that is used in Channel to decorate the
        authentication methods here.

        Args:
            auth_username: username for authentication
            auth_password: password for authentication
            auth_bypass: bypass authentication process
            timeout_socket: timeout for establishing socket in seconds -- since this is not directly
                exposed in telnetlib, this is just the initial timeout for the telnet connection.
                After the connection is established, the timeout is modified to the value of
                `timeout_transport`.
            timeout_transport: timeout for telnet transport in seconds
            timeout_ops: timeout for telnet channel operations in seconds -- this is also the
                timeout for finding and responding to username and password prompts at initial
                login. This is assigned to a private attribute and is ignored after authentication
                is completed.
            timeout_exit: True/False close transport if timeout encountered. If False and keepalives
                are in use, keepalives will prevent program from exiting so you should be sure to
                catch Timeout exceptions and handle them appropriately
            keepalive: whether or not to try to keep session alive
            keepalive_interval: interval to use for session keepalives
            keepalive_type: network|standard -- 'network' sends actual characters over the
                transport channel. This is useful for network-y type devices that may not support
                "standard" keepalive mechanisms. 'standard' is not currently implemented for telnet
            keepalive_pattern: pattern to send to keep network channel alive. Default is
                u'\005' which is equivalent to 'ctrl+e'. This pattern moves cursor to end of the
                line which should be an innocuous pattern. This will only be entered *if* a lock
                can be acquired. This is only applicable if using keepalives and if the keepalive
                type is 'network'
            comms_prompt_pattern: prompt pattern expected for device, same as the one provided to
                channel -- telnet needs to know this to know how to decide if we are properly
                sending/receiving data -- i.e. we are not stuck at some password prompt or some
                other failure scenario. If using driver, this should be passed from driver (Scrape,
                or IOSXE, etc.) to this Transport class. This is assigned to a private attribute and
                is ignored after authentication is completed.
            comms_return_char: return character to use on the channel, same as the one provided to
                channel -- telnet needs to know this to know what to send so that we can probe
                the channel to make sure we are authenticated and sending/receiving data. If using
                driver, this should be passed from driver (Scrape, or IOSXE, etc.) to this Transport
                class. This is assigned to a private attribute and is ignored after authentication
                is completed.
            comms_ansi: True/False strip comms_ansi characters from output; this value is assigned
                self._comms_ansi and is ignored after authentication. We only need it for transport
                on the off chance (maybe never, especially here in telnet land?) that
                username/password prompts contain ansi characters, otherwise "comms_ansi" is really
                a channel attribute and is treated as such. This is assigned to a private attribute
                and is ignored after authentication is completed.

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        super().__init__(
                host="dummy"
            # host=None,
            # port=None,
            # timeput_socket=timeout_socket,
            # timeout_transport=timeout_transport,
            # timeout_exit=timeout_exit,
            # keepalive,
            # keepalive_interval,
            # keepalive_type,
            # keepalive_pattern,
        )
        self.auth_username: str = auth_username
        self.auth_password: str = auth_password
        self.auth_bypass: bool = auth_bypass

        self._timeout_ops: int = timeout_ops
        # timeout_ops_auth is only used for authentication; base ops timeout * 2 as we are doing
        # two operations -- entering username and entering password (in most cases at least)
        self._timeout_ops_auth: int = timeout_ops * 2

        self._comms_prompt_pattern: str = comms_prompt_pattern
        self._comms_return_char: str = comms_return_char
        self._comms_ansi: bool = comms_ansi

        self.username_prompt: str = "Username:"
        self.password_prompt: str = "Password:"

        if transport_options is None:
            self.transport_options: Optional[Dict[str, Any]] = {}
        else:
            self.transport_options: Optional[Dict[str, Any]] = transport_options

        # set the timeout for the serial connection to 0.
        # this results in read() returning everything that is currently available
        self.transport_options["timeout"] = 1

        self.console: Serial = None
        self.lib_auth_exception = ScrapliAuthenticationFailed
        self._isauthenticated = False

    def open(self) -> None:
        """
        Open channel, acquire pty, request interactive shell

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        from serial import Serial
        self.session_lock.acquire()
        if self.console is None:
            self.console = Serial(**self.transport_options)

            # send RETURN to enable the shell
            self.write("\r\n")
        self.session_lock.release()

    def read(self) -> bytes:
        """
        Read data from the channel

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        read_block_size: int = 128
        output: str = b""
        while True:
            iteration_output = self.console.read(read_block_size)
            print(iteration_output)
            output += iteration_output
            if len(iteration_output) < read_block_size:
                return output

    def write(self, channel_input: str) -> None:
        """
        Write data to the channel

        Args:
            channel_input: string to send to channel

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        self.console.write(channel_input.encode())

    def _session_keepalive(self) -> None:
        """
        Spawn keepalive thread for transport session

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        # This does not need a keepalive
        pass

    def close(self) -> None:
        """
        """
        if self.console is not None:
            self.session_lock.acquire()
            self.console.close()
            self.console = None
            self.session_lock.release()

    def isalive(self) -> bool:
        """
        Check if socket is alive and session is authenticated

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        return self.serial is not None

    def set_timeout(self, timeout: Optional[int] = None) -> None:
        """
        Set session timeout

        Args:
            timeout: timeout in seconds

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        # this method is not needed for serial devices
        pass

    def _keepalive_standard(self) -> None:
        """
        Send "out of band" (protocol level) keepalives to devices.

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        # this method is not needed for serial devices
        pass
