# password validation

import webapp2
import cgi
import re

form="""
<form method="post">
    <b>Enter user name, password and email:</b>
    <table>
    <tr>
        <td>
            user name:<input type="text" name="username">
        </td>
        <td style="color: red">
            %(usernameerror)s
        </td>
    </tr>
    <tr>
        <td>
            password:<input type="password" name="password">
        </td>
        <td style="color: red">
            %(passworderror)s
        </td>
    </tr>
    <tr>
        <td>
            verify:<input type="password" name="verify">
        </td>
        <td style="color: red">
            %(verifyerror)s
        </td>
    </tr>
    <tr>
        <td>
            email:<input type="text" name="email">
        </td>
        <td style="color: red">
            %(emailerror)s
        </td>
    </tr>
    </table>
    <input type="submit">
</form>
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def escape_html(s):
    return cgi.escape(s, quote = True)

def validate_username(user_name):
    return USER_RE.match(user_name)

def validate_password(password):
    return PASS_RE.match(password)

def validate_email(email):
    return EMAIL_RE.match(email)

class MainPage(webapp2.RequestHandler):
    def write_form(self,username_error="",password_error="",verify_error="",email_error=""):
        self.response.out.write(form % {"usernameerror":username_error,"passworderror":password_error,"verifyerror":verify_error,"emailerror":email_error})

    def get(self):
        self.write_form()

    def post(self):
        user_name=self.request.get('username')
        user_password=self.request.get('password')
        user_verify=self.request.get('verify')
        user_email=self.request.get('email')
        username_error=""
        password_error=""
        verify_error=""
        email_error=""

        if not validate_username(user_name):
            username_error="please enter valid user name"

        if not validate_password(user_password):
            password_error = "please enter valid password"

        if not user_password == user_verify:
            verify_error="passwords don't match"

        if not validate_email(user_email):
            email_error = "please enter valid email id"

        if (validate_username(user_name) and validate_password(user_password) and (user_password == user_verify) and validate_email(user_email)):
            self.redirect("/unit2/signup/Welcome?username=" + user_name)
        else:
            self.write_form(username_error,password_error,verify_error,email_error)
        #self.write_form("",escape_html(rot13_text))

class Welcome(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Welcome " + self.request.get('username'))

app = webapp2.WSGIApplication([('/unit2/signup', MainPage),('/unit2/signup/Welcome', Welcome)], debug=True)
