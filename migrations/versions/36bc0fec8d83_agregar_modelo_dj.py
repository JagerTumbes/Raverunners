"""Agregar modelo DJ

Revision ID: 36bc0fec8d83
Revises: 1d8d9d19e10b
Create Date: 2025-03-01 01:18:05.074415

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '36bc0fec8d83'
down_revision = '1d8d9d19e10b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('djs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre_dj', sa.String(length=80), nullable=False),
    sa.Column('descripcion', sa.Text(), nullable=True),
    sa.Column('foto', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['id'], ['usuarios.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('djs')
    # ### end Alembic commands ###
