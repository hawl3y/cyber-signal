import logging
from logging.config import fileConfig

from alembic import context

from app import create_app
from app.extensions import db

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.env")

app = create_app()


def get_engine():
    return db.engine


def get_engine_url():
    try:
        return get_engine().url.render_as_string(hide_password=False).replace("%", "%%")
    except AttributeError:
        return str(get_engine().url).replace("%", "%%")


def get_metadata():
    return db.metadata


def run_migrations_offline():
    """
    Run migrations in 'offline' mode.
    """
    with app.app_context():
        config.set_main_option("sqlalchemy.url", get_engine_url())
        url = config.get_main_option("sqlalchemy.url")

        context.configure(
            url=url,
            target_metadata=get_metadata(),
            literal_binds=True,
        )

        with context.begin_transaction():
            context.run_migrations()


def run_migrations_online():
    """
    Run migrations in 'online' mode.
    """
    with app.app_context():
        config.set_main_option("sqlalchemy.url", get_engine_url())

        def process_revision_directives(context_, revision, directives):
            if getattr(config.cmd_opts, "autogenerate", False):
                script = directives[0]
                if script.upgrade_ops.is_empty():
                    directives[:] = []
                    logger.info("No changes in schema detected.")

        connectable = get_engine()

        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=get_metadata(),
                process_revision_directives=process_revision_directives,
            )

            with context.begin_transaction():
                context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()