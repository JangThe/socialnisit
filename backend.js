import express from 'express';
import mysql from 'mysql2';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const port = 3000;
const app = express();
app.use(express.json());

const JWT_SECRET = 'tajny-token-klic';

const db = mysql.createConnection({
    host: 'mysqlstudenti.litv.sssvt.cz',
    user: 'sarkezisamuel',
    password: '123456',
    database: '4a1_sarkezisamuel_db2'  
});

db.connect((err) => {
    if (err) {
        console.log('Chyba databaze:', err);
        return;
    }
    console.log('Databaze pripojeno!');
});

function overitPrihlaseni(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ zprava: 'Chybi token.' });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, uzivatel) => {
        if (err) {
            return res.status(403).json({ zprava: 'Neplatny token.' });
        }

        req.uzivatel = uzivatel;
        next();
    });
}

app.get('/', (req, res) => {
    res.status(200).send('API bezi!');
});


app.post('/auth/registrace', (req, res) => {
    const { jmeno, prijmeni, vek, pohlavi, email, heslo } = req.body;

    if (!jmeno || !prijmeni || !vek || !email || !heslo) {
        return res.status(400).json({ zprava: 'Vyplň vsechna pole.' });
    }

    if (vek < 13) {
        return res.status(400).json({ zprava: 'Musi byt starsi 13 let.' });
    }

    bcrypt.hash(heslo, 10, (err, hash) => {
        if (err) return res.status(500).json({ zprava: 'Chyba hesla.' });

        db.query(
            'INSERT INTO uzivatele (jmeno, prijmeni, vek, pohlavi, email, heslo) VALUES (?, ?, ?, ?, ?, ?)',
            [jmeno, prijmeni, vek, pohlavi, email, hash],
            (err, vysledek) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(400).json({ zprava: 'Email uz existuje.' });
                    }
                    return res.status(500).json({ zprava: 'Chyba registrace.' });
                }

                res.status(201).json({
                    zprava: 'Registrace OK!',
                    id: vysledek.insertId
                });
            }
        );
    });
});


app.post('/auth/prihlaseni', (req, res) => {
    const { email, heslo } = req.body;

    if (!email || !heslo) {
        return res.status(400).json({ zprava: 'Zadej email a heslo.' });
    }

    db.query('SELECT * FROM uzivatele WHERE email = ?', [email], (err, vysledky) => {
        if (err) return res.status(500).json({ zprava: 'Chyba prihlaseni.' });

        if (vysledky.length === 0) {
            return res.status(401).json({ zprava: 'Spatny email nebo heslo.' });
        }

        const uzivatel = vysledky[0];

        bcrypt.compare(heslo, uzivatel.heslo, (err, shoda) => {
            if (err || !shoda) {
                return res.status(401).json({ zprava: 'Spatny email nebo heslo.' });
            }

            const token = jwt.sign(
                {
                    id: uzivatel.id,
                    jmeno: uzivatel.jmeno,
                    prijmeni: uzivatel.prijmeni,
                    email: uzivatel.email
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.status(200).json({
                zprava: 'Prihlaseni OK!',
                token
            });
        });
    });
});


app.post('/auth/odhlaseni', (req, res) => {
    res.status(200).json({ zprava: 'Odhlaseni proved na klientovi (smaz token).' });
});


app.get('/prispevky', overitPrihlaseni, (req, res) => {
    db.query(`
        SELECT p.id, p.nadpis, p.text, p.obrazek, p.datum_vytvoreni,
            u.id AS autor_id, u.jmeno, u.prijmeni,
            COUNT(DISTINCT l.id) AS pocet_laiku
        FROM prispevky p
        JOIN uzivatele u ON p.autor_id = u.id
        LEFT JOIN laiky l ON p.id = l.prispevek_id
        GROUP BY p.id
        ORDER BY p.datum_vytvoreni DESC
    `, (err, data) => {
        if (err) return res.status(500).json({ zprava: 'Chyba nacitani.' });
        res.json(data);
    });
});


app.post('/prispevky', overitPrihlaseni, (req, res) => {
    const { nadpis, text, obrazek } = req.body;

    if (!nadpis || !text) {
        return res.status(400).json({ zprava: 'Nadpis a text jsou povinne.' });
    }

    db.query(
        'INSERT INTO prispevky (autor_id, nadpis, text, obrazek) VALUES (?, ?, ?, ?)',
        [req.uzivatel.id, nadpis, text, obrazek || null],
        (err, vysledek) => {
            if (err) return res.status(500).json({ zprava: 'Chyba vytvareni.' });

            res.status(201).json({
                zprava: 'Prispevek pridan!',
                id: vysledek.insertId
            });
        }
    );
});


app.post('/komentare', overitPrihlaseni, (req, res) => {
    const { prispevek_id, text } = req.body;

    db.query(
        'INSERT INTO komentare (autor_id, prispevek_id, text) VALUES (?, ?, ?)',
        [req.uzivatel.id, prispevek_id, text],
        (err, vysledek) => {
            if (err) return res.status(500).json({ zprava: 'Chyba komentare.' });

            res.status(201).json({
                zprava: 'Komentar pridan!',
                id: vysledek.insertId
            });
        }
    );
});


app.post('/laiky', overitPrihlaseni, (req, res) => {
    const { prispevek_id } = req.body;

    db.query(
        'INSERT INTO laiky (uzivatel_id, prispevek_id) VALUES (?, ?)',
        [req.uzivatel.id, prispevek_id],
        (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ zprava: 'Uz jsi lajkoval.' });
                }
                return res.status(500).json({ zprava: 'Chyba lajku.' });
            }

            res.json({ zprava: 'Lajknuto!' });
        }
    );
});


app.listen(port, () => {
    console.log(`Server bezi na portu ${port}`);
});