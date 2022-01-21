from flask import Flask, render_template, redirect, url_for, flash, request, g, session, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
#from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, Login, CommentField
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import ForeignKey



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##Parent
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="comment_author")

##Child
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250),  nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    ##Relationship one to many
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = db.relationship("User", back_populates="posts")

    # comment blogpost one to many relationship
    comments = db.relationship("Comment", back_populates="parent_post")

#CHILD
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    ##Relationship one to many
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = db.relationship("User", back_populates="comments")

    # one to many relationship posts
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = db.relationship("BlogPost", back_populates="comments")


#db.create_all()

# config of application
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    g.user = user_id
    return User.query.get(int(user_id))

# only admins can delete post or change


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        if current_user.is_authenticated and session["id"] == 1:
            return f(*args, **kws)
        else:
           abort(403)
    return decorated_function


@app.route('/')
def get_all_posts():
    #checks if it is the admin who can delete stuff
    is_admin=False
    if current_user.is_authenticated and session["id"] == 1:
        is_admin=True

    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, is_admin=is_admin)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if db.session.query(User.id).filter_by(email=email).first() is not None:
            flash("You are already signed up by that email, login instead")
            return redirect(url_for("login"))
        else:
            # hash the password
            new_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

            # fill into the database
            user = User(name=name,
                        email=email,
                        password=new_password)


            # fill database
            db.session.add(user)
            db.session.commit()
            login_user(user)
            session['id'] = user.id
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login = Login()
    if login.validate_on_submit():
        try:
            user = User.query.filter_by(email=request.form.get('email')).first()
            if check_password_hash(user.password, request.form.get('password')):
                login_user(user)
                db.session['id'] = user.id
                return redirect(url_for("get_all_posts"))
            else:
                flash('Login Unsuccessful. Please check your password', 'danger')
                return redirect(url_for("login"))
        except:
            flash('Login Unsuccessful. Please check your email', 'danger')
            return redirect(url_for("login"))


    return render_template("login.html", form=login, logged_in=current_user.is_authenticated)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    if current_user.is_authenticated and session["id"] == 1:
        is_admin=True
    else:
        is_admin = False

    commentfield = CommentField()
    if commentfield.validate_on_submit():
        if current_user.is_authenticated:
            text = request.form.get('comment')
            # fill database
            comment = Comment(text=text, comment_author=current_user, parent_post=requested_post)
            db.session.add(comment)
            db.session.commit()
        else:
            flash("You are not logged in. Please log in")
            return redirect(url_for("login"))

    comments = Comment.query.all()
    return render_template("post.html", post=requested_post, is_admin=is_admin, form=commentfield, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
