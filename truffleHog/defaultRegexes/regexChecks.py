regexes = {
    #"Internal subdomain": re.compile('([a-z0-9]+[.]*supersecretinternal[.]com)'),
    "slack_token": '(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
    "rsa_private_key": '-----BEGIN RSA PRIVATE KEY-----',
    "ssh_openssh_private_key": '-----BEGIN OPENSSH PRIVATE KEY-----',
    "ssh_dsa_private_key": '-----BEGIN DSA PRIVATE KEY-----',
    "ssh_ec_private_key": '-----BEGIN EC PRIVATE KEY-----',
    "pgp_private_key_block": '-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "facebook_oauth": '[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|"][0-9a-f]{32}[\'|"]',
    "twitter_oauth": '[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|"][0-9a-zA-Z]{35,44}[\'|"]',
    "github": '[g|G][i|I][t|T][h|H][u|U][b|B].*[[\'|"]0-9a-zA-Z]{35,40}[\'|"]',
    "google_oauth": '("client_secret":"[a-zA-Z0-9-_]{24}")',
    "aws_api_key": 'AKIA[0-9A-Z]{16}',
    "heroku_api_key": '[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    "generic_secret": '[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]',
}

