"""empty message

Revision ID: 5642b2a7fc21
Revises: 36bc0fec8d83
Create Date: 2025-03-02 15:08:46.462005

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '5642b2a7fc21'
down_revision = '36bc0fec8d83'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('ravers', schema=None) as batch_op:
        batch_op.drop_column('codigo_qr')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('ravers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('codigo_qr', mysql.VARCHAR(length=1000), nullable=False))

    # ### end Alembic commands ###
