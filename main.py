#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import re

template_dir = os.path.join(os.path.dirname(__file__),"templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
PASSWORD_RE = re.compile(r'^.{3,20}$')

def valid_email(email):
    return EMAIL_RE.match(email)

def valid_name(name):
    return USER_RE.match(name)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_verify_password(password, verify_password):
    if password == verify_password:
        return True


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(Handler):
    def get(self):
        self.render("index.html")

    def post(self):
        # Error messages
        username_error = invalid_email = invalid_password = verify_password_error = None

        user_username = self.request.get("username")
        user_password = self.request.get("password")
        user_verify_password = self.request.get("verify")
        user_email = self.request.get("email")

        username = valid_name(user_username)
        password = valid_password(user_password)
        verify_password = None
        email = None

        if user_email:
            email = valid_email(user_email)
            if not email:
                invalid_email = "That's not a valid email."

        if not username:
            username_error = "That's not a valid username."

        if password:
            verify_password = valid_verify_password(user_password, user_verify_password)
            if not verify_password:
                verify_password_error = "Your passwords didn't match."
        else:
            invalid_password = "That wasn't a valid password."

        if username and password and verify_password and not invalid_email:
            self.redirect("/welcome?username=%s"%(user_username))
        else:
            self.render("index.html",
            username_error = username_error,
            username = user_username,
            invalid_password = invalid_password,
            verify_password_error = verify_password_error,
            invalid_email = invalid_email,
            email = user_email)

class WelcomePage(Handler):
    def get(self):
        username = self.request.get("username")
        self.write("Thanks for signing up %s" % (username))

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/welcome',WelcomePage)
], debug=True)
