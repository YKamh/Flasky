from flask import render_template, redirect, request, url_for, flash
from flask_login import logout_user, login_required, login_user, current_user
from . import auth
from ..models import User, email_confirm
from .forms import LoginForm, RegistrationForm, ModifyForm, MailconfirmForm, ResetPasswordForm, ChangeemailForm
from .. import db
from ..email import send_email
import hashlib


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account', 'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.route('/change_confirm/<token>')
def change_confirm(token):
    if email_confirm(token) is not None:
        return redirect(url_for('auth.reset_password', mail=email_confirm(token)))
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account', 'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


@auth.route('/modify', methods=['GET', 'POST'])
@login_required
def modify():
    form = ModifyForm()
    if current_user.is_anonymous:
        return redirect(url_for('main.index'))
    if form.validate_on_submit():
        if current_user.verify_password(form.oldpassword.data):
            current_user.password = form.newpassword.data
            db.session.add(current_user)
            db.session.commit()
            flash('You Password has been update')
            return redirect(url_for('auth.login'))
        else:
            flash('Your operation is wrong.')
    return render_template('auth/modify.html', form=form)


@auth.route('/reset_password/<mail>', methods=['GET', 'POST'])
def reset_password(mail):
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=mail).first()
        user.password = form.newpassword.data
        db.session.add(user)
        db.session.commit()
        flash('You Password has been update.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('auth/send_email_confirm', methods=['GET', 'POST'])
def send_email_confirm():
    form = MailconfirmForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        token = user.generate_mail_confirmation_token()
        send_email(user.email, 'Confirm Your Account', 'auth/email/reset_pwd_confirm', user=user, token=token)
        return redirect(url_for('auth.login'))
    return render_template('auth/mail_confirm.html', form=form)


@auth.route('auth/fill_change_email_form', methods=['GET', 'POST'])
@login_required
def fill_change_email_form():
    form = ChangeemailForm()
    if form.validate_on_submit():
        token = current_user.generate_new_mail_confirmation_token(form.new_email.data)
        send_email(form.new_email.data, 'Confirm Your New Email', 'auth/email/confirm_new_email',
                   user=current_user, token=token)
        return redirect(url_for('main.index'))
    return render_template('auth/fill_change_email_form.html', form=form)


@auth.route('auth/update_new_email/<token>', methods=['GET', 'POST'])
@login_required
def update_new_email(token):
    if current_user.new_email_confirm(token) is not None:
        current_user.email = current_user.new_email_confirm(token)
        current_user.avatar_hash = hashlib.md5(current_user.email.encode('utf-8')).hexdigest()
        db.session.add(current_user)
        db.session.commit()
        flash('You Email has been update.')
        return redirect(url_for('main.index'))
    else:
        flash('The confirmation link is invalid or has expired.')
