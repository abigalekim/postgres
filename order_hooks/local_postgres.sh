# CAUTION: run this script from the home directory

# build and install extension from source
cd ./order_hooks
make USE_PGXS=1
sudo make USE_PGXS=1 install

# create the database and launch it
cd ..
/usr/local/pgsql/bin/initdb -D ./order_hooks_data 
/usr/local/pgsql/bin/postgres -D ./order_hooks_data