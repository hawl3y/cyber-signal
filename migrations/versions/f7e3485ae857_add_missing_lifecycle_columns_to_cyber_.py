"""add missing lifecycle columns to cyber_events

Revision ID: f7e3485ae857
Revises: 3f432f9e8d06
Create Date: 2026-04-14 14:13:53.964501

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f7e3485ae857'
down_revision = 'b090f192c94b'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("cyber_events", sa.Column("verification_level", sa.String(length=50), nullable=True))
    op.add_column("cyber_events", sa.Column("record_origin", sa.String(length=50), nullable=True))
    op.add_column("cyber_events", sa.Column("is_high_impact", sa.Boolean(), nullable=True))

    op.execute("UPDATE cyber_events SET verification_level = 'low' WHERE verification_level IS NULL")
    op.execute("UPDATE cyber_events SET record_origin = 'live_detection' WHERE record_origin IS NULL")
    op.execute("UPDATE cyber_events SET is_high_impact = false WHERE is_high_impact IS NULL")


def downgrade():
    op.drop_column("cyber_events", "verification_level")
    op.drop_column("cyber_events", "record_origin")
    op.drop_column("cyber_events", "is_high_impact")