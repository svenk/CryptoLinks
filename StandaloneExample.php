<h1>Standalone CryptoLinks demonstrator</h1>

<p>1. Setting up CryptoLinker instance</p>

<?php

require_once 'CryptoLinks.class.php';

$l = new CryptoLinker();

# add demonstrator files. The filenames are secrets.
$l->files[] = '/etc/passwd';
$l->files[] = '/etc/motd';

# add random payload. This is visible for the client.
$l->vars['foo'] = 'bar';

?>

<p>2. Obtain an encrypted link:</p>

<?php

$url =  $l->get_secure_link();
print "<a href='$url'>$url</a>";

?>

<p>3. Decrypting what is given in the PATH.</p>

<pre><?php

$p = new CryptoLinker();
$p->read_secure_link($_GET);
print_r($p->files);

?></pre>

