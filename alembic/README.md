# Alembic

## Quick Notes

The `env.py` file in this directory is set up to look interact with the db
using the same mechanisms and config as our project itself. What this means
is that, with the propery Dynaconf settings, `alembic` commands will work
directly with our configured database.

When making migrations, you **must not** use `sqlite` and instead prefer the
target database e.g. `postgres`. This is because [`sqlite's` `ALTER` syntax](https://sqlite.org/lang_altertable.html)
is a limited subset of what is available in other databases. As such, alterations
we may make as part of a migration are **not** supported in `sqlite`.

## How to make a change

`alembic` is a tool for codifying changes to our database and produces files
that allow us to both `upgrade` and `downgrade` our databse based on those
changes. This allows us to adapt our existing databases in production over time.

In this way, `alembic` is to our database what `git` is to our code.

To make a change:

In a fresh, up-to-date git branch in the project root:

* Ensure your locally configured db (test.db is the default in our Dyanconf settings) is up-to-date by `running alembic upgrade` head. This executes all migrations in the project against the db and records that state info in your test.db
* Make the change in models and orm
* Execute `alembic revision --autogenerate -m"Message that describes what you did"`. You'll see a new file in `alembic/versions` that is not yet tracked in git. Look at this file and make sure the upgrade and downgrade changes make sense. For example, if you added a new column, `upgrade` should try to create the column and `downgrade` should try to remove it.
* Once you're satisfied that is correct and all of the db changes you need, add the file to git so it gets tracked with the project

## What to do with an existing DB that hasn't used alembic yet

Assuming the production db matches your current set of migrations i.e. that if
you ran all migrations, the db structure would be the same as what is in production,
then you can do `alembic stamp head` while connected to the production db to label
production's current state as matching the latest migration revision. This writes
to a special table in your db for `alembic` to let the tool know what revision it's
on. Future migrations can then be applied by running `alembic upgrade head`.
