import os
import webapp2
import jinja2

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape=True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self,template,**parms):
        t=jinja_env.get_template(template)
        return t.render(parms)

    def render(self, template, **kw):
        self.write(self.render_str(template,**kw))

class MainPage(Handler):
    def get(self):
        items=self.request.get_all("food")
        self.render('shopping_list.html', items=items)

class BuzzHandler(Handler):
    def get(self):
        self.render('fizzbuzz.html',n=int(self.request.get("n")))


app = webapp2.WSGIApplication([('/', MainPage),('/fizzbuzz',BuzzHandler)],debug=True)
