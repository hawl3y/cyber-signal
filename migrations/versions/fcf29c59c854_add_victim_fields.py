"""add victim fields

Revision ID: fcf29c59c854
Revises: f7e3485ae857
Create Date: 2026-04-14

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fcf29c59c854'
down_revision = 'f7e3485ae857'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("cyber_events", sa.Column("victim_entity_type", sa.String(length=100), nullable=True))
    op.add_column("cyber_events", sa.Column("victim_display_label", sa.String(length=255), nullable=True))

    op.add_column("article_extractions", sa.Column("victim_entity_type", sa.String(length=100), nullable=True))
    op.add_column("article_extractions", sa.Column("victim_display_label", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("cyber_events", "victim_entity_type")
    op.drop_column("cyber_events", "victim_display_label")

    op.drop_column("article_extractions", "victim_entity_type")
    op.drop_column("article_extractions", "victim_display_label")