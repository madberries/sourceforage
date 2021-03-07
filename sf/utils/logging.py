import os
import sys

from colors import ansilen, color, partial
from enum import Enum

from .string import make_title, pad_with_spaces, screen_width, wrap_text

# Local "constants"
FAIL_SIGN = '\u274c'    # Red crossed-out mark
PASS_SIGN = '\u2705'    # Green check mark
WARN_SIGN = str(b'\xe2\x9a\xa0\xef\xb8\x8f\x27', 'utf-8')
TOP_FMT = '%s,---- [START OF %s]'
TOP_FMT_WCAP = '%s,---- [%s]'
BOT_FMT = '%s`---- [END OF %s] %s'
BOT_FMT_WCAP = '%s`---- [%s] %s'
CAPTION_SEP = ' :: '

SECTION_COLOR = partial(color, fg=255, bg=237)
TITLE_COLOR = partial(color, fg=255, bg=237, style='underline')
EXEC_COLOR = partial(color, fg=40, bg=255)
INFO_COLOR = partial(color, fg=237, bg=255)
DEBUG_COLOR = partial(color, fg=245, bg=255)
WARN_COLOR = partial(color, fg=128, bg=255)
ERROR_COLOR = partial(color, fg=196, bg=255, style='bold')
SUCCESS_COLOR = partial(color, fg=46, bg=16, style='bold')
HARDFAIL_COLOR = partial(color, fg=196, bg=16, style='bold')
SOFTFAIL_COLOR = partial(color, fg=190, bg=16, style='bold')


class LoggingException(Exception):
    pass


class StepFailedException(Exception):
    pass


class LogStatus(Enum):

    def __new__(cls, value, label, offset):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.label = label
        obj.offset = offset
        return obj

    PASS = (0, PASS_SIGN, 1)
    SOFT_FAIL = (1, WARN_SIGN, -1)
    HARD_FAIL = (2, FAIL_SIGN, 1)


class LogSection:

    def __init__(self, msg, step, title=None, caption=None):
        self.msg = msg
        self.title = title
        self.caption = caption
        self.depth = len(step)
        self.step = '.'.join(map(str, step))
        self.status = LogStatus.PASS

    def start_section(self):
        print(self.section0())

    def end_section(self):
        print(self.section0(is_start=False))

    def section0(self, is_start=True):
        empty_msg = True
        indent_str = '| ' * (self.depth - 1)
        left_margin = f"{indent_str}| "
        max_width = screen_width()

        # If this isn't the end section, and there isn't already a title
        # specified, and we have overridden the caption, then let's be
        # helpful and make the step be the title.
        if self.title is None:
            if is_start and self.caption is not None:
                title = f'{self.step})'
            else:
                title = None
        else:
            title = f'{self.title}:'

        # If there is a message, then refit the message body inside of
        # of this section.
        msg = self.msg
        if msg != '':
            empty_msg = False
            fmtd_body = ''    # The entire body of the constructed message

            # If there is a title, then make sure the lines are indented
            # properly for all remaining lines (after the first).
            if title is not None:
                indent = len(title) + 1
                width = max_width - indent - (self.depth * 2) - 1
                msg = wrap_text(msg, width=width,
                                indent_on_newline=indent).strip()

            # Reformat the message body into the header/footer.
            for i, line in enumerate(msg.split('\n')):
                if i == 0 and title is not None:
                    # This is the first line of the header, and we are
                    # including a title, so lets fit it to the line.  We
                    # have already adjusted the insets for any subsequent
                    # line.
                    fmtd_prefix = SECTION_COLOR(left_margin) + \
                            TITLE_COLOR(title)
                    fitted_cols = max_width - ansilen(fmtd_prefix)
                    fmtd_line = SECTION_COLOR(
                        pad_with_spaces(f' {line}', cols=fitted_cols)
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

        # By default, the caption here will be the step number (i.e. '1.2.2')
        # unless one is supplied.
        if self.caption is None:
            caption = self.step
        else:
            caption = self.caption

        cols = max_width
        if is_start:
            # Start section case:
            fmtd_prefix = SECTION_COLOR(
                pad_with_spaces(TOP_FMT % (indent_str, caption))
            )
            #if title is None:
            #    return f"{fmtd_prefix}\n{fmtd_body}"
            suffix = left_margin
        else:
            # End section case:
            fmtd_prefix = SECTION_COLOR(pad_with_spaces(left_margin))
            suffix = BOT_FMT % (indent_str, caption, self.status.label)
            # Adjust the number of columns to be fitted, since the symbol sizes
            # apparently vary.
            cols -= self.status.offset

        fmtd_suffix = SECTION_COLOR(pad_with_spaces(suffix, cols=cols))
        if empty_msg:
            return f"{fmtd_prefix}\n{fmtd_suffix}"

        return f"{fmtd_prefix}\n{fmtd_body}{fmtd_suffix}"


class ItemizedLogger:

    def __init__(self):
        self.step_stack = []
        self.task_stack = []
        self.last_popped = 0

        # Print the legend at the top
        e = ERROR_COLOR('This is an ERROR')
        w = WARN_COLOR('This is a WARNING')
        i = INFO_COLOR('This is an INFO')
        d = DEBUG_COLOR('This is a DEBUG')
        print(f"{e} {w} {i} {d}")

    ####################################
    # The standard logging mechanisms: #
    ####################################

    def info(self, msg):
        self.log(msg, text_color=INFO_COLOR)

    def debug(self, msg):
        self.log(msg, text_color=DEBUG_COLOR)

    def warn(self, msg):
        self.log(msg, text_color=WARN_COLOR, file=sys.stderr)

    def error(self, msg):
        self.log(msg, text_color=ERROR_COLOR, file=sys.stderr)

    ####################################
    # General log routines:            #
    ####################################
    def log(
        self,
        msg,
        text_color=INFO_COLOR,
        show_status=False,
        file=sys.stdout,
        end='\n'
    ):
        for msg in msg.splitlines():
            self.log0(
                msg,
                text_color=text_color,
                show_status=show_status,
                file=file,
                end=end
            )

    def log0(
        self,
        msg,
        text_color=INFO_COLOR,
        show_status=False,
        file=sys.stdout,
        end='\n'
    ):
        if len(self.step_stack) == 0:
            raise LoggingException

        # Compute the number of columns to the end of the screen.
        depth = len(self.step_stack)
        fitted_cols = screen_width() - (depth * 2)
        cols_offset = self.task_stack[-1].status.offset

        # Wrap all of the lines such that they fit within the number of columns
        # available after the margin.
        lines = wrap_text(msg, width=fitted_cols).splitlines()
        last_line_idx = len(lines) - 1
        for idx, line in enumerate(lines):
            left_margin = SECTION_COLOR('| ' * depth)
            if show_status and idx == last_line_idx:
                # Adjust the fitted columns based on the 'size' of the symbol.
                fitted_cols -= cols_offset
                status = self.task_stack[-1].status.label
                line += f" {status}"
            print(left_margin, end="", file=file)
            print(
                text_color(pad_with_spaces(line, cols=fitted_cols)),
                file=file,
                end=end
            )

    def log_exception(self, trace):
        self.info(make_title('exception', width=40))
        self.error(trace)

    ############################################################
    # Critical step that determines pass/fail of step/substep  #
    ############################################################

    def success(self, msg):
        if len(self.step_stack) == 0:
            raise LoggingException
        task_item = self.task_stack[-1]
        # A hard failure should have immediately returned to the previous step.
        # A soft failure is OK!
        if task_item.status is LogStatus.HARD_FAIL:
            raise LoggingException
        task_item.status = LogStatus.PASS
        self.log(msg, text_color=SUCCESS_COLOR, show_status=True)

    def soft_fail(self, msg):
        if len(self.step_stack) == 0:
            raise LoggingException
        task_item = self.task_stack[-1]
        # A hard failure should have immediately returned to the previous step.
        if task_item.status is LogStatus.HARD_FAIL:
            raise LoggingException
        task_item.status = LogStatus.SOFT_FAIL
        self.log(
            msg, text_color=SOFTFAIL_COLOR, file=sys.stderr, show_status=True
        )

    def hard_fail(self, msg, soft=False):
        if len(self.step_stack) == 0:
            raise LoggingException
        self.task_stack[-1].status = LogStatus.HARD_FAIL
        self.log(
            msg, text_color=HARDFAIL_COLOR, file=sys.stderr, show_status=True
        )
        raise StepFailedException

    ############################################################
    # Creating and Completing new subtasks:                    #
    ############################################################

    def new_substep(self, msg, title=None, caption=None):
        self.step_stack.append(self.last_popped + 1)

        # Prepend the caption (if there is one) with the task's caption at the
        # top of the stack (if there is one).
        if caption is not None and len(self.task_stack) > 0:
            top_caption = self.task_stack[-1].caption
            if top_caption is not None:
                caption = f'{top_caption}{CAPTION_SEP}{caption}'

        # Generate and start the new log section.
        task_item = LogSection(
            msg, self.step_stack, title=title, caption=caption
        )
        self.task_stack.append(task_item)
        task_item.start_section()
        self.last_popped = 0    # Reset this, since we just pushed a new task.

        # return the status of the new task (for convenience).  This should
        # always be LogStatus.PASS.
        return task_item.status

    def complete_substep(self, msg='', title=None):
        # Make sure there are tasks on the stack to complete!
        if len(self.step_stack) == 0:
            raise LoggingException

        # Complete the top-most task on the stack (overwriting both the message
        # and title).
        task_item = self.task_stack.pop()
        task_item.msg = msg
        task_item.title = title
        task_item.end_section()

        # Set the last subsection number that we popped, and return the status
        # of this completed task.
        self.last_popped = self.step_stack.pop()
        return task_item.status
