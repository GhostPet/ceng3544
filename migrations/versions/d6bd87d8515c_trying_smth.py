"""Trying smth

Revision ID: d6bd87d8515c
Revises: 86a0dd876e7f
Create Date: 2024-06-08 03:04:53.282291

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd6bd87d8515c'
down_revision = '86a0dd876e7f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('qr_approved', sa.Boolean(), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('qr_approved')

    # ### end Alembic commands ###
