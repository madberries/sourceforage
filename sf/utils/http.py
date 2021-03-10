import itertools
import re

from bs4 import BeautifulSoup

from .string import make_title


def get_all_forms(url, session, log):
    """Returns all form tags found on a web page's `url` """
    # Issue the GET request.
    res = session.get(url)

    # Make sure the response was OK.
    if res.status_code != 200:
        log.error(
            f"HTTP GET request for {url} returned erroneous response code "
            f"({page.status_code})"
        )
        return None

    # Parse and pretty-print the HTML response.
    soup = BeautifulSoup(res.html.html, "html5lib")
    log.debug(make_title('start of HTTP response'))
    log.debug(soup.prettify())
    log.debug(make_title('end of HTTP response'))

    # Return the forms generated from this response.
    return soup.find_all("form"), soup


def get_form_details(form):
    """Returns the HTML details of a form,
    including action, method and list of form controls (inputs, etc)"""
    details = {}

    # Get the form action (requested URL).
    action = form.attrs.get("action").lower()

    # Get the form method (POST, GET, DELETE, etc).  If not specified, GET is
    # the default.
    method = form.attrs.get("method", "get").lower()

    # Get all of the inputs to this form.
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type, "name": input_name, "value": input_value
        })

    # Additionally, we must include any textarea, since this is technically
    # also an input field that will get appended to the query string.  Without
    # this, the request might not process (due to missing query parameters).
    #
    # TODO: Are there other non-standard "<input>"-like tags we need to concern
    #       ourselves with??
    for input_tag in form.find_all("textarea"):
        input_name = input_tag.attrs.get("name")
        inputs.append({
            "type": "textarea", "name": input_name, "value": input_tag.string
        })

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def fill_form(
    data, input_tag_name, to_match, replacement_list, log, fallback=None
):
    if fallback is not None:
        # If there is a fallback, then we will try to match that last.
        replacement_list = replacement_list.copy()
        replacement_list[0].append(fallback)
    for varname, value_to_replace in itertools.product(*replacement_list):
        if bool(re.match(rf"^([^_]*_)?{varname}$", to_match)):
            data[input_tag_name] = value_to_replace
            log.info(
                f"Appending {input_tag_name}={value_to_replace} to the request"
            )
            return True
    return False
