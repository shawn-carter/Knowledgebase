=========================
Welcome to Knowledgebase!
=========================

Source code
  http://github.com/shawn-carter/Knowledgebase

Installation and Setup
======================

First, setup the repo:

.. code:: bash

    git clone http://github.com/shawn-carter/Knowledgebase

Change Directory to Knowledgebase

.. code:: bash

    cd Knowledgebase

Create a Virtal Environment

.. code:: bash

    python3 -m venv venv

Activate the New Environment

.. code:: bash

    source venv/bin/activate # On Windows: venv\Scripts\activate

Install Dependencies

.. code:: bash

    pip install -r requirements.txt

SetUp the Database
  Update the settings.py file in the myknowledgebase directory with your database settings.

.. code:: python

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'your_db_name',
            'USER': 'your_db_user',
            'PASSWORD': 'your_db_password',
            'HOST': 'your_db_host',
            'PORT': 'your_db_port',
        }
    }

Run Migrations

.. code:: python

    python manage.py makemigrations
    python manage.py migrate

Create a Superuser (Optional)

.. code:: python

    python manage.py createsuperuser

Collect Static Files (if needed)
        
.. code:: python

    python manage.py createsuperuser

Run the Development Server

.. code:: python

    python manage.py runserver

Models
======

The ``KBEntry`` model represents a KnowledgeBase Article  - this is the main model in the application, 
holding the details of the Article along with things like upvotes, rating, author, created date etc.

The ``Tags`` model is used to hold all the Metadata Tags

The ``Audit`` model is used to store and track events such as Article creation, editting and deletions.
