Virtualenv
===========

    sudo pip install virtualenv

create the virtualenv directory

    virtualenv ~/virtualenv

activate the virtualenv:

    source ~/virtualenv/bin/activate
    
Postgressql
===========

    sudo apt-get install postgresql 
    sudo apt-get install pgadmin3
    
bitcoinlib
===========

add this line in your bashrc

    export PYTHONPATH=$PYTHONPATH:REPOSVN/coinplus/bitcoinlib/trunk/src/


changing postgres password
--------------------------

    sudo -s
    su -l postgres
    psql
    \password postgres
    
Installing coinplus/web javascript
==================================

    cd REPOSVN/coinplus/trunk/web_client/static-src
    npm install 
    # may be this as well or node node_modules/bower/bin/bower.js instead of bower
    # npm install -g bower gulp
    bower install
    gulp


Installing coinplus/web
========================

    (virtualenv)$ cd REPOSVN/coinplus/trunk/web/src
    (virtualenv)$ python setup.py develop
    (virtualenv)$ pserve --reload FILE.ini 
    
    
