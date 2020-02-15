"""scrapli.helper"""
import importlib
import os
import re
import warnings
from io import TextIOWrapper
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, TextIO, Union

import pkg_resources  # pylint: disable=C0411


def get_prompt_pattern(prompt: str, class_prompt: str) -> Pattern[bytes]:
    r"""
    Return compiled prompt pattern

    Given a potential prompt and the Channel class' prompt, return compiled prompt pattern

    Args:
        prompt: bytes string to process
        class_prompt: Channel class' prompt pattern

    Returns:
        output: bytes string each line right stripped

    Raises:
        N/A

    """
    check_prompt = prompt or class_prompt
    if isinstance(check_prompt, str):
        bytes_check_prompt = check_prompt.encode()
    else:
        bytes_check_prompt = check_prompt
    if bytes_check_prompt.startswith(b"^") and bytes_check_prompt.endswith(b"$"):
        return re.compile(bytes_check_prompt, flags=re.M | re.I)
    return re.compile(re.escape(bytes_check_prompt))


def normalize_lines(output: bytes) -> bytes:
    r"""
    Normalize lines

    Split output lines to remove \r\n, rstrip each line and rejoin

    Args:
        output: bytes string to process

    Returns:
        bytes: bytes string each line right stripped

    Raises:
        N/A

    """
    return b"\n".join([line.rstrip() for line in output.splitlines()])


def strip_ansi(output: bytes) -> bytes:
    """
    Strip comms_ansi

    Strip comms_ansi characters from output

    Args:
        output: bytes from previous reads if needed

    Returns:
        bytes: bytes output read from channel with comms_ansi characters removed

    Raises:
        N/A

    """
    ansi_escape_pattern = re.compile(rb"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    output = re.sub(ansi_escape_pattern, b"", output)
    return output


def validate_external_function(possible_function: Union[Callable[..., Any], str]) -> bool:
    """
    Validate string representing external function is a callable

    Args:
        possible_function: string "pointing" to external function

    Returns:
        bool: True if provided string/callable is valid function, else False

    Raises:
        N/A

    """
    try:
        if not isinstance(possible_function, str):
            return False
        if "." not in possible_function:
            return False
        ext_func_path = possible_function.split(".")
        ext_module = ".".join(ext_func_path[:-1])
        importlib.import_module(ext_module)
        return True
    except ModuleNotFoundError:
        return False


def get_external_function(external_function_path: str) -> Callable[..., Any]:
    """
    Return callable from external file

    Args:
        external_function_path: string "pointing" to external function

    Returns:
        ext_func: callable imported from external_function_path

    Raises:
        N/A

    """
    ext_func_path = external_function_path.split(".")
    ext_module_name = ".".join(ext_func_path[:-1])
    ext_function = ext_func_path[-1]
    ext_module = importlib.import_module(ext_module_name)
    ext_func: Callable[..., Any] = getattr(ext_module, ext_function)
    return ext_func


def _textfsm_get_template(platform: str, command: str) -> Optional[TextIO]:
    """
    Find correct TextFSM template based on platform and command executed

    Args:
        platform: ntc-templates device type; i.e. cisco_ios, arista_eos, etc.
        command: string of command that was executed (to find appropriate template)

    Returns:
        None or TextIO of opened template

    Raises:
        N/A

    """
    try:
        from textfsm.clitable import CliTable  # pylint: disable=C0415
    except ModuleNotFoundError as exc:
        err = f"Module '{exc.name}' not installed!"
        msg = f"***** {err} {'*' * (80 - len(err))}"
        fix = (
            f"To resolve this issue, install '{exc.name}'. You can do this in one of the following"
            " ways:\n"
            "1: 'pip install -r requirements-textfsm.txt'\n"
            "2: 'pip install scrapli[textfsm]'"
        )
        warning = "\n" + msg + "\n" + fix + "\n" + msg
        warnings.warn(warning)
        return None
    template_dir = pkg_resources.resource_filename("ntc_templates", "templates")
    cli_table = CliTable("index", template_dir)
    template_index = cli_table.index.GetRowMatch({"Platform": platform, "Command": command})
    if not template_index:
        return None
    template_name = cli_table.index.index[template_index]["Template"]
    template = open(f"{template_dir}/{template_name}")
    return template


def textfsm_parse(
    template: Union[str, TextIOWrapper], output: str
) -> Optional[Union[List[Any], Dict[str, Any]]]:
    """
    Parse output with TextFSM and ntc-templates, try to return structured output

    Args:
        template: TextIOWrapper or string path to template to use to parse data
        output: unstructured output from device to parse

    Returns:
        output: structured data

    Raises:
        N/A

    """
    import textfsm  # pylint: disable=C0415

    if not isinstance(template, TextIOWrapper):
        template_file = open(template)
    else:
        template_file = template
    re_table = textfsm.TextFSM(template_file)
    try:
        structured_output: Union[List[Any], Dict[str, Any]] = re_table.ParseText(output)
        return structured_output
    except textfsm.parser.TextFSMError:
        pass
    return None


def resolve_ssh_config(ssh_config_file: str) -> str:
    """
    Resolve ssh configuration file from provided string

    If provided string is empty (`""`) try to resolve system ssh config files located at
    `~/.ssh/config` or `/etc/ssh/ssh_config`.

    Args:
        ssh_config_file: string representation of ssh config file to try to use

    Returns:
        str: string to path fro ssh config file or an empty string

    Raises:
        N/A

    """
    if Path(ssh_config_file).is_file():
        return str(Path(ssh_config_file))
    if Path(os.path.expanduser("~/.ssh/config")).is_file():
        return str(Path(os.path.expanduser("~/.ssh/config")))
    if Path("/etc/ssh/ssh_config").is_file():
        return str(Path("/etc/ssh/ssh_config"))
    return ""
