"""Initial Migration

Revision ID: db89a9ea7b78
Revises:
Create Date: 2022-08-06 04:49:56.644137

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'db89a9ea7b78'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
                    sa.Column('id', sa.CHAR(length=36), nullable=False),
                    sa.Column('username', sa.VARCHAR(length=64), nullable=False),
                    sa.Column('email', sa.VARCHAR(length=128), nullable=False),
                    sa.Column('password', sa.VARCHAR(length=102), nullable=False),
                    sa.Column('email_validated', sa.Boolean(), server_default='0', nullable=False),
                    sa.Column('enabled', sa.Boolean(), server_default='1', nullable=False),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('email'),
                    sa.UniqueConstraint('username')
                    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    # ### end Alembic commands ###
