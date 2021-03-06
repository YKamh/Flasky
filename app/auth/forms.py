from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me Logged in')
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                                                         'Usernames must have only letters,'
                                                                                         'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[DataRequired(),
                                                     EqualTo('password2', message='Password must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class ModifyForm(FlaskForm):
    oldpassword = PasswordField('OldPassword', validators=[DataRequired()])
    newpassword = PasswordField('NewPassword', validators=[DataRequired(),
                                                           EqualTo('newpassword2', message='Password must match.')])
    newpassword2 = PasswordField('Confirm new password', validators=[DataRequired()])
    submit = SubmitField('Commit')


class MailconfirmForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('Mailbox authentication')

class ResetPasswordForm(FlaskForm):
    newpassword = PasswordField('NewPassword', validators=[DataRequired(),
                                                           EqualTo('newpassword2', message='Password must match.')])
    newpassword2 = PasswordField('Confirm new password', validators=[DataRequired()])
    submit = SubmitField('Commit')


class ChangeemailForm(FlaskForm):
    new_email = StringField('New Email', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('Go to New Email Confirm')

    def validate_new_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
