import os
import sys

from colors import ansilen, color, partial

from .string import make_title, pad_with_spaces, screen_width, wrap_text

# Local "constants"
FAIL_SIGN = '\u274c'    # Red crossed-out mark
PASS_SIGN = '\u2705'    # Green check mark
TOP_FMT = '%s,---- [START OF %s]'
BOT_FMT = '%s`---- [END OF %s] %s'

SECTION_COLOR = partial(color, fg=255, bg=237)
TITLE_COLOR = partial(color, fg=255, bg=237, style='underline')
EXEC_COLOR = partial(color, fg=40, bg=255)
INFO_COLOR = partial(color, fg=237, bg=255)
DEBUG_COLOR = partial(color, fg=245, bg=255)
WARN_COLOR = partial(color, fg=128, bg=255)
ERROR_COLOR = partial(color, fg=196, bg=255, style='bold')
SUCCESS_COLOR = partial(color, fg=46, bg=16, style='bold')
FAIL_COLOR = partial(color, fg=196, bg=16, style='bold')


class LoggingException(Exception):
    pass


class StepFailedException(Exception):
    pass


class LogSection:

    def __init__(self, msg, step, title=None):
        self.msg = msg
        self.title = title
        self.depth = len(step)
        self.step = '.'.join(map(str, step))

    def start_section(self):
        print(
            LogSection.section0(
                self.msg, self.step, True, depth=self.depth, title=self.title
            )
        )

    def end_section(self, success=True):
        print(
            LogSection.section0(
                self.msg,
                self.step,
                False,
                depth=self.depth,
                title=self.title,
                success=success
            )
        )

    @staticmethod
    def section0(msg, step, start, depth=0, title=None, success=False):
        empty_msg = True
        indent_str = '| ' * (depth - 1)
        left_margin = f"{indent_str}| "
        max_width = screen_width()

        # If there is a message, then refit the message body inside of
        # of this section.
        if msg != '':
            empty_msg = False
            fmtd_body = ''    # The entire body of the constructed message

            # If there is a title, then make sure the lines are indented
            # properly for all remaining lines (after the first).
            if title is not None:
                indent = len(title) + 2
                width = max_width - indent
                msg = wrap_text(msg, width=width, indent_on_newline=indent)

            first_line = True
            lines = msg.split('\n')
            for line in msg.split('\n'):
                if first_line and title is not None:
                    # This is the first line of the header, and we are
                    # including a title, so lets fit it to the line.  We
                    # have already adjusted the insets for any subsequent
                    # line.
                    fmtd_prefix = SECTION_COLOR(left_margin) + \
                            TITLE_COLOR(title)
                    fitted_cols = max_width - ansilen(fmtd_prefix)
                    fmtd_line = SECTION_COLOR(
                        pad_with_spaces(f": {line}", cols=fitted_cols)
                    )
                    fmtd_body += fmtd_prefix + fmtd_line
                else:
                    # Since this is not the title line, nothing special
                    # needs to be done here outside of padding the message
                    # to the body to fit the screen width.
                    fmtd_body += SECTION_COLOR(
                        pad_with_spaces(left_margin + line)
                    )
                fmtd_body += '\n'
                first_line = False

        cols = max_width
        if start:
            # Start section case:
            fmtd_prefix = SECTION_COLOR(
                pad_with_spaces(TOP_FMT % (indent_str, step))
            )
            suffix = left_margin
        else:
            # End section case:
            if success:
                pass_or_fail = PASS_SIGN
            else:
                pass_or_fail = FAIL_SIGN
            fmtd_prefix = SECTION_COLOR(pad_with_spaces(left_margin))
            suffix = BOT_FMT % (indent_str, step, pass_or_fail)
            cols -= 1    # Note: pass/fail marks appear to consume a couple
            # of characters in the terminal.

        fmtd_suffix = SECTION_COLOR(pad_with_spaces(suffix, cols=cols))
        if empty_msg:
            return f"{fmtd_prefix}\n{fmtd_suffix}"

        return f"{fmtd_prefix}\n{fmtd_body}{fmtd_suffix}"


class ItemizedLogger:

    def __init__(self):
        self.step_stack = [0]
        self.task_stack = []
        self.last_popped = 0
        self.task_running = False

        # Print the legend at the top
        e = ERROR_COLOR('This is an ERROR')
        w = WARN_COLOR('This is a WARNING')
        i = INFO_COLOR('This is an INFO')
        d = DEBUG_COLOR('This is a DEBUG')
        print(f"{e} {w} {i} {d}")

    def info(self, msg):
        self.log(msg, text_color=INFO_COLOR)

    def debug(self, msg):
        self.log(msg, text_color=DEBUG_COLOR)

    def warn(self, msg):
        self.log(msg, text_color=WARN_COLOR, file=sys.stderr)

    def error(self, msg):
        self.log(msg, text_color=ERROR_COLOR, file=sys.stderr)

    def success(self, msg):
        self.log(msg, text_color=SUCCESS_COLOR, mark_success=True)

    def fail(self, msg):
        self.log(
            msg, text_color=FAIL_COLOR, file=sys.stderr, mark_success=False
        )

    def log(
        self, msg, text_color=INFO_COLOR, mark_success=None, file=sys.stdout
    ):
        lines = msg.splitlines()
        last_line_idx = len(lines) - 1
        for idx, line in enumerate(lines):
            depth = len(self.step_stack)
            left_margin = SECTION_COLOR('| ' * depth)
            fitted_cols = screen_width() - (depth * 2)
            if mark_success is not None and idx == last_line_idx:
                fitted_cols -= 1
                if mark_success:
                    pass_or_fail = PASS_SIGN
                else:
                    pass_or_fail = FAIL_SIGN
                line += f" {pass_or_fail}"
            print(left_margin, end="", file=file)
            print(
                text_color(pad_with_spaces(line, cols=fitted_cols)), file=file
            )

    def log_exception(self, trace):
        self.info(make_title('exception', width=40))
        self.error(trace)

    def new_task(self, msg, title=None, subtask=False):
        if not subtask and self.task_running:
            raise LoggingException
        self.step_stack[-1] += 1
        self.task_stack.append(LogSection(msg, self.step_stack, title=title))
        self.task_stack[-1].start_section()
        self.task_running = True
        self.last_popped = 0

    def new_subtask(self, msg, title=None):
        self.step_stack.append(self.last_popped)
        self.last_popped = 0
        self.new_task(msg, title=title, subtask=True)

    def complete_subtask(self, msg='', title=None, success=True):
        self.complete_task(msg, title=title, success=success, subtask=True)

    def complete_task(self, msg='', title=None, success=True, subtask=False):
        #if not self.task_running:
        #    raise ItemizedLogException
        task_item = self.task_stack.pop()
        if subtask:
            self.last_popped = self.step_stack.pop()
        task_item.msg = msg    # Write over previous message
        task_item.title = title    # Write over previous title
        task_item.end_section(success=success)
        self.task_running = False
