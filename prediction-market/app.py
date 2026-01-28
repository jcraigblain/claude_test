"""
Prediction Market Web Application
A lightweight prediction market for small organizations.
"""

import os
import hashlib
import secrets
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///predictions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =============================================================================
# Database Models
# =============================================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    balance = db.Column(db.Float, default=100.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    predictions = db.relationship('Prediction', backref='creator', lazy=True)
    bets = db.relationship('Bet', backref='user', lazy=True)

    def set_password(self, password):
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        self.password_hash = f"{salt}${hash_obj.hex()}"

    def check_password(self, password):
        try:
            salt, hash_hex = self.password_hash.split('$')
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hash_obj.hex() == hash_hex
        except:
            return False

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'balance': round(self.balance, 2),
            'created_at': self.created_at.isoformat()
        }


class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolves_at = db.Column(db.DateTime, nullable=False)
    resolved = db.Column(db.Boolean, default=False)
    outcome = db.Column(db.Boolean, nullable=True)  # True = Yes, False = No, None = unresolved

    bets = db.relationship('Bet', backref='prediction', lazy=True)

    def get_pool_info(self):
        """Calculate total bets for yes and no positions."""
        yes_total = sum(b.amount for b in self.bets if b.position)
        no_total = sum(b.amount for b in self.bets if not b.position)
        total = yes_total + no_total

        # Calculate implied probability
        yes_prob = (yes_total / total * 100) if total > 0 else 50
        no_prob = (no_total / total * 100) if total > 0 else 50

        return {
            'yes_total': round(yes_total, 2),
            'no_total': round(no_total, 2),
            'total': round(total, 2),
            'yes_probability': round(yes_prob, 1),
            'no_probability': round(no_prob, 1),
            'bet_count': len(self.bets)
        }

    def to_dict(self, include_bets=False):
        pool_info = self.get_pool_info()
        data = {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'creator_id': self.creator_id,
            'creator_email': self.creator.email,
            'created_at': self.created_at.isoformat(),
            'resolves_at': self.resolves_at.isoformat(),
            'resolved': self.resolved,
            'outcome': self.outcome,
            **pool_info
        }
        if include_bets:
            data['bets'] = [b.to_dict() for b in self.bets]
        return data


class Bet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prediction_id = db.Column(db.Integer, db.ForeignKey('prediction.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    position = db.Column(db.Boolean, nullable=False)  # True = Yes, False = No
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user_email': self.user.email,
            'prediction_id': self.prediction_id,
            'amount': round(self.amount, 2),
            'position': 'Yes' if self.position else 'No',
            'created_at': self.created_at.isoformat()
        }


# =============================================================================
# Authentication Helpers
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Please log in to continue'}), 401
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


# =============================================================================
# Page Routes
# =============================================================================

@app.route('/')
def index():
    return render_template('index.html')


# =============================================================================
# API Routes - Authentication
# =============================================================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400

    email = data['email'].lower().strip()
    password = data['password']

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'An account with this email already exists'}), 400

    user = User(email=email)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    session['user_id'] = user.id

    return jsonify({
        'message': 'Account created successfully! You start with $100.',
        'user': user.to_dict()
    }), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400

    email = data['email'].lower().strip()
    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401

    session['user_id'] = user.id

    return jsonify({
        'message': 'Logged in successfully',
        'user': user.to_dict()
    })


@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'})


@app.route('/api/me')
def get_me():
    user = get_current_user()
    if not user:
        return jsonify({'user': None})
    return jsonify({'user': user.to_dict()})


# =============================================================================
# API Routes - Predictions
# =============================================================================

@app.route('/api/predictions')
def list_predictions():
    sort = request.args.get('sort', 'recent')
    show_resolved = request.args.get('resolved', 'false') == 'true'

    query = Prediction.query

    if not show_resolved:
        query = query.filter_by(resolved=False)

    if sort == 'recent':
        query = query.order_by(Prediction.created_at.desc())
    elif sort == 'soonest':
        query = query.filter(Prediction.resolves_at >= datetime.utcnow())
        query = query.order_by(Prediction.resolves_at.asc())
    elif sort == 'active':
        # Sort by number of bets (most active first)
        query = query.outerjoin(Bet).group_by(Prediction.id)
        query = query.order_by(func.count(Bet.id).desc())

    predictions = query.all()

    return jsonify({
        'predictions': [p.to_dict() for p in predictions]
    })


@app.route('/api/predictions/<int:prediction_id>')
def get_prediction(prediction_id):
    prediction = Prediction.query.get_or_404(prediction_id)
    return jsonify({'prediction': prediction.to_dict(include_bets=True)})


@app.route('/api/predictions', methods=['POST'])
@login_required
def create_prediction():
    data = request.get_json()
    user = get_current_user()

    if not data or not data.get('title') or not data.get('resolves_at'):
        return jsonify({'error': 'Title and resolution date are required'}), 400

    try:
        resolves_at = datetime.fromisoformat(data['resolves_at'].replace('Z', '+00:00'))
        if resolves_at.tzinfo:
            resolves_at = resolves_at.replace(tzinfo=None)
    except:
        return jsonify({'error': 'Invalid date format'}), 400

    if resolves_at <= datetime.utcnow():
        return jsonify({'error': 'Resolution date must be in the future'}), 400

    prediction = Prediction(
        title=data['title'],
        description=data.get('description', ''),
        creator_id=user.id,
        resolves_at=resolves_at
    )

    db.session.add(prediction)
    db.session.commit()

    return jsonify({
        'message': 'Prediction created successfully',
        'prediction': prediction.to_dict()
    }), 201


@app.route('/api/predictions/<int:prediction_id>/bet', methods=['POST'])
@login_required
def place_bet(prediction_id):
    data = request.get_json()
    user = get_current_user()
    prediction = Prediction.query.get_or_404(prediction_id)

    if prediction.resolved:
        return jsonify({'error': 'This prediction has already been resolved'}), 400

    if prediction.resolves_at <= datetime.utcnow():
        return jsonify({'error': 'Betting is closed for this prediction'}), 400

    if not data or 'amount' not in data or 'position' not in data:
        return jsonify({'error': 'Amount and position are required'}), 400

    try:
        amount = float(data['amount'])
    except:
        return jsonify({'error': 'Invalid amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    if amount > user.balance:
        return jsonify({'error': f'Insufficient balance. You have ${user.balance:.2f}'}), 400

    position = data['position'] in [True, 'yes', 'Yes', 'YES', 1, '1']

    bet = Bet(
        user_id=user.id,
        prediction_id=prediction_id,
        amount=amount,
        position=position
    )

    user.balance -= amount

    db.session.add(bet)
    db.session.commit()

    return jsonify({
        'message': f'Bet placed successfully! ${amount:.2f} on {"Yes" if position else "No"}',
        'bet': bet.to_dict(),
        'new_balance': round(user.balance, 2)
    }), 201


@app.route('/api/predictions/<int:prediction_id>/resolve', methods=['POST'])
@login_required
def resolve_prediction(prediction_id):
    data = request.get_json()
    user = get_current_user()
    prediction = Prediction.query.get_or_404(prediction_id)

    if prediction.creator_id != user.id:
        return jsonify({'error': 'Only the creator can resolve this prediction'}), 403

    if prediction.resolved:
        return jsonify({'error': 'This prediction has already been resolved'}), 400

    if 'outcome' not in data:
        return jsonify({'error': 'Outcome is required'}), 400

    outcome = data['outcome'] in [True, 'yes', 'Yes', 'YES', 1, '1']
    prediction.resolved = True
    prediction.outcome = outcome

    # Calculate winnings and distribute
    pool_info = prediction.get_pool_info()
    total_pool = pool_info['total']

    if total_pool > 0:
        winning_pool = pool_info['yes_total'] if outcome else pool_info['no_total']

        if winning_pool > 0:
            # Winners split the entire pool proportionally
            for bet in prediction.bets:
                if bet.position == outcome:
                    share = bet.amount / winning_pool
                    winnings = total_pool * share
                    bet.user.balance += winnings

    db.session.commit()

    return jsonify({
        'message': f'Prediction resolved as {"Yes" if outcome else "No"}',
        'prediction': prediction.to_dict()
    })


@app.route('/api/my-bets')
@login_required
def my_bets():
    user = get_current_user()
    bets = Bet.query.filter_by(user_id=user.id).order_by(Bet.created_at.desc()).all()

    return jsonify({
        'bets': [{
            **b.to_dict(),
            'prediction_title': b.prediction.title,
            'prediction_resolved': b.prediction.resolved,
            'prediction_outcome': b.prediction.outcome
        } for b in bets]
    })


# =============================================================================
# Initialize Database
# =============================================================================

with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True, port=5000)
