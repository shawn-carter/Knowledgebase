=========================
Welcome to Knowledgebase!
=========================
This application was written by me, using Django with SQLiteDB for an assignment for a level 5 module called 'Software Engineering and Agile' in 2023.
It is now being updated for a level 6 module called 'Software Engineering and Agile' - and has had some improvements.
The application makes use of several libraries, including Bootstrap5, jQuery, DataTables.js, Quill.js and Alertify.js

It is a simple application, incorporating user login and registration, password reset via link.

New Features:
  + Application is now hosted on Azure as a web app, and uses GitHub Actions workflow to build/test and deploy upon a push to this repo.
  + Now sends emails via Azure Communications for password reset.
  + MFA has been added, again sending an email with a 6 digit PIN.

New Security:
  + Content Security Policy - using middleware that creates nonce for inpage scripts.
  + Security Headers - to prevent XSS, etc
  + Environment Variables - DB Connection details are kept in the Azure WebApp Configuration, along with SECRET_KEY and AZURE COMMS CONNECTION STRING
  + Secure Cookies/Session Cookies
  + HSTS enabled - also Azure is set to HTTPS only
  + Microsoft SQL Server for production (based on environmental variable 'ENVIRONMENT' = 'PRODUCTION')
  + All JS/CSS is hosted from domain

Logged in users can:
  + Search the Knowledgebase
      - This searches in the article title, article body and for author name.
      - Search results are displayed in a paginated table and allows access to the article details via a link, but also allows a user to click on the author (to see all articles by this author), or they can click on the Metadata Tags to perform a search for all articles with that tag.
      - Search results can be sorted by Title, Author, Article Extract or Metatags, a user can also filter the search results with the table search.
      - Columns can be re-arranged.
      - If there are less than 5 articles returned in a search (or when the search page is opened) then the top 5 rated articles, and the newest 5 articles are shown below the search bar/search results.
  + Create a New Article - utilising a Quill.js editor, the user can create a rich text article, and add meta tags.
      - Metatags can be created or selected from a drop down which utilises a lookup based on the text being typed.
  + See article details, shows the article title and article content, and shows article information including: Author, Created Date, Last Modified By and Date, Views and Rating along with Metatags.
  
  + Edit their own articles, using similar page to create, the title, article body can be modified - and tags can be added or removed.
  + See All Articles - Like the search results these can be sorted by Title, Rating, Summary, Created By, Created Date or Tags.
      - Links to the article details, all articles by an author and links to search for metatags are displayed in the view.
  + My Articles - Shows a list of all your articles, can again be sorted by any column.
      - Anywhere the article title is displayed, it shows a badge - the colour of the badge reflects the user rating
          + Red for poor (25% or less)
          + Orange for below average (26-49%)
          + Yellow for averate (50-74%)
          + Green for good (75%+)
          + Grey for articles that have not yet been rated
      - The number in the badge is the amount of times the article has been viewed.
      - Any article not written by the logged in user can be up or downvoted (you cannot vote on your own articles)
  + Change their password - you need to give your old password + valid password x2
  + Log out - with confirmation.

Admin (SuperUsers) can also:
  + Look at the audit logs, in a datatable - that can be filtered with a search box, the results are paginated.  Logs are created when an article is created, modified, soft deleted and permanently deleted.
  + Manage Metatags, tags can be deleted (whether they are used or not) - this can be used to delete orphaned tags (where an article has been permanently deleted, the tag is not removed intentionally).
  + List all users, and has the ability to Enable and Disable User Accounts - user is not allowed to disable their own account for obvious reasons.
  + See All Articles, allows SuperUser to see all articles (including those which have been soft deleted) - articles can be edited or soft deleted from this view (without confirmation) for ease of use.
  + See article details - allows the SuperUser to Edit or Soft Delete any article (with confirmation). 
      - Soft deleted articles are not returned in search results, or any other view (such as my articles etc).
      - When an article is soft deleted, it can be permanently deleted - I only added this feature to meet the needs of showing full CRUD capabilities. The article can also be undeleted from the soft deleted state.
      - If an article is permanently deleted then references to the article in the audit logs are removed and replaced with N/A, but the audit log still shows that the article was created, edited or deleted.
Admin users cannot up or downvote articles (intentional).
  
Source code
  http://github.com/shawn-carter/Knowledgebase

Working demonstration
  https://azure.shwan.tech

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

SetUp the Database (Optional) -- You can use the included sqlite3 Database - and create a new SuperUser [Jump to Create a Superuser](#create_superuser) or
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

Create a Superuser (Just do this if you are using the SQLite3 DB)

<a id="create_superuser"></a>
.. code:: python

    python manage.py createsuperuser

Collect Static Files (if needed)
        
.. code:: python

    python manage.py collectstatic

Run the Development Server

.. code:: python

    python manage.py runserver

Models
======

The ``KBEntry`` model represents a KnowledgeBase Article  - this is the main model in the application, 
holding the details of the Article along with things like upvotes, rating, author, created date etc.

The ``Tags`` model is used to hold all the Metadata Tags.

The ``Audit`` model is used to store and track events such as Article creation, editting and deletions.

The ``User`` model is the Django built in User model.

Testing
=======
I used Django built in tests - there are over 100 tests, testing the models, forms and views - with unit tests and some integration tests.
To run the tests

.. code:: python

    python manage.py test

