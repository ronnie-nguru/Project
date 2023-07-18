from datetime import datetime
import os
from flask import render_template, flash, redirect, url_for, request, g, \
        jsonify, current_app, make_response
from flask_login import current_user, login_required
from sqlalchemy import and_, or_
from app import db
from app.main.forms import EditProfileForm, EmptyForm, MessageForm, AssociationForm
from app.models import User, Message, Notification, Association
from app.main import bp
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

@bp.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()


@bp.route('/add_association', methods=['GET', 'POST'])
@login_required
def add_association():
    association_form = AssociationForm()

    if association_form.validate_on_submit():
        user_id = association_form.assoc_user_id.data
        username = association_form.assoc_username.data

        user = User.query.filter_by(id=user_id, username=username).first()
        association = Association.query.filter_by(
                associator_id = current_user.id, associated_id = user_id).first()
        if not user:
            flash('User not found.')
        elif association:
            flash('Association already exists with {}.'.format(user.username))
        else:
            association = Association(associator_id=current_user.id, associated_id=user_id)
            db.session.add(association)
            db.session.commit()
            flash('Association request sent to {}.'.format(user.username))
            return redirect(url_for('main.add_association'))
    return render_template('add_association.html', association_form = association_form)


@bp.route('/select_user/<int:user_id>')
@login_required
def select_user(user_id):
    response = make_response(redirect(url_for('main.index')))
    response.set_cookie('selected_user_id', str(user_id), max_age = 60 * 60)
    return response


@bp.route('/', methods=['GET', 'POST'])
@bp.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    # Get the IDs of users with two-way associations with the current user
    associated_user_ids = db.session.query(Association.associator_id).filter(
        Association.associated_id == current_user.id,
        Association.is_blocked == False
    ).subquery()

    # Fetch the users with two-way associations
    users = User.query.filter(
        User.id != current_user.id,
        User.id.in_(associated_user_ids),
        User.id.in_(db.session.query(Association.associated_id).filter(
            Association.associator_id == current_user.id,
            Association.is_blocked == False
        ))
    ).order_by(User.username.asc()).all()

    selected_user_id = 0
    if request.cookies.get('selected_user_id') is not None:
        selected_user_id = int(request.cookies.get('selected_user_id'))

    messages = None
    selected_user = None
    if selected_user_id != 0:
        selected_user = User.query.filter_by(id=selected_user_id).first_or_404()

        messages = Message.query.filter(
            or_(
                (Message.sender_id == current_user.id) & (Message.recipient_id == selected_user_id),
                (Message.sender_id == selected_user_id) & (Message.recipient_id == current_user.id)
            )
        ).order_by(Message.timestamp.asc())

    return render_template('index.html', users=users, selected_user_id=selected_user_id,
                           selected_user=selected_user, messages=messages)


@bp.route('/user/<username>')
@login_required
def user(username):
    return render_template('user.html')


@bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('main.edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
    return render_template('edit_profile.html', title='Edit Profile',
            form=form)

@bp.route('/send_message', methods=['POST'])
@login_required
def send_message():
    message = request.form.get('message-input')
    selected_user_id = 0

    if message == '':
        return

    if request.cookies.get('selected_user_id') is not None:
        selected_user_id = int(request.cookies.get('selected_user_id'))
    user = User.query.filter_by(id=selected_user_id).first_or_404()
    msg = Message(author=current_user, recipient=user, body=message)

    # Handling image upload
    image_file = request.files.get('image')
    if image_file:
        # Renaming the image to current timestamp
        timestamp = int(datetime.timestamp(datetime.utcnow()))
        filename = f"{timestamp}.{image_file.filename.split('.')[-1]}"
        message_image_path = os.path.join(current_app.static_folder, 'images', 'messages')
        os.makedirs(message_image_path, exist_ok=True)
        image_path = os.path.join(message_image_path, filename)
        image_file.save(image_path)
        msg.image_url = f"images/messages/{filename}"

    db.session.add(msg)
    user.add_notification('unread_message_count', user.new_messages())
    db.session.commit()
    return redirect(url_for('main.index'))


@bp.route('/notifications')
@login_required
def notifications():
    since = request.args.get('since', 0.0, type=float)
    notifications = current_user.notifications.filter(
            Notification.timestamp > since).order_by(Notification.timestamp.asc())
    return jsonify([{
        'name': n.name,
        'data': n.get_data(),
        'timestamp': n.timestamp
        } for n in notifications])


@bp.route('/block_user/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    association = Association.query.filter_by(associator_id=current_user.id,
            associated_id=user_id, is_blocked=False).first_or_404()
    association.is_blocked = True
    db.session.commit()
    flash('User {} has been blocked.'.format(user.username))
    return redirect(url_for('main.blocked'))


@bp.route('/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    association = Association.query.filter_by(associator_id=current_user.id,
            associated_id=user_id, is_blocked=True).first_or_404()
    association.is_blocked = False
    db.session.commit()
    flash('User {} has been unblocked.'.format(user.username))
    return redirect(url_for('main.blocked'))


@bp.route('/blocked')
@login_required
def blocked():
    blocked_users = Association.query.filter_by(associator_id = current_user.id, is_blocked=True)\
            .join(User, User.id == Association.associated_id)\
            .add_columns(User.id, User.username)
    unblocked_users = Association.query.filter_by(associator_id = current_user.id, is_blocked=False)\
            .join(User, User.id == Association.associated_id)\
            .add_columns(User.id, User.username)
    return render_template('blocked.html', blocked_users=blocked_users, unblocked_users = unblocked_users)

@bp.route('/pending_requests', methods=['GET', 'POST'])
@login_required
def pending_requests():
    sent_associations = Association.query.filter_by(associator_id=current_user.id) \
        .join(User, User.id == Association.associated_id) \
        .add_columns(User.id, User.username)

    accepted_associations = Association.query.filter_by(associated_id=current_user.id) \
        .join(User, User.id == Association.associator_id) \
        .add_columns(User.id, User.username)

    pending_associations = [association for association in sent_associations
                            if association.id not in [accepted.id for accepted in accepted_associations]]

    accepting_associations = [association for association in accepted_associations
                              if association.id not in [sent.id for sent in sent_associations]]

    return render_template('pending_requests.html', pending_associations=pending_associations,
                           accepting_associations=accepting_associations)


@bp.route('/accept_association/<int:association_id>', methods=['GET', 'POST'])
@login_required
def accept_association(association_id):
    association = Association.query.get_or_404(association_id)
    reversed_association = Association.query.filter_by(associator_id = current_user.id, 
            associated_id = association.associator_id).first()

    if reversed_association:
        flash("You are already associated with this user.")
        return redirect(url_for('main.pending_requests'))

    if association.associated_id == current_user.id:
        association.is_blocked = False
        reversed_association = Association(
                associator_id=current_user.id,
                associated_id=association.associator_id,
                is_blocked=False
                )
        db.session.add(reversed_association)
        db.session.commit()
        flash('You are now associated with {}.'.format(association.username))
    return redirect(url_for('main.pending_requests'))

