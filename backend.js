import express from 'express';
import mysql from 'mysql2';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';

const port = 3000;
const app = express();
app.use(express.json());
app.use(cors());

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
app.get('/prispevky/:id', overitPrihlaseni, (req, res) => {
    const id = req.params.id;
    db.query(`
        SELECT p.id, p.nadpis, p.text, p.obrazek, p.datum_vytvoreni,
            u.id AS autor_id, u.jmeno, u.prijmeni,
            COUNT(DISTINCT l.id) AS pocet_laiku
        FROM prispevky p
        JOIN uzivatele u ON p.autor_id = u.id
        LEFT JOIN laiky l ON p.id = l.prispevek_id
        WHERE p.id = ?
        GROUP BY p.id
    `, [id], (err, vysledky) => {
        if (err) return res.status(500).json({ zprava: 'Chyba.' });
        if (vysledky.length === 0) return res.status(404).json({ zprava: 'Nenalezen.' });
        const prispevek = vysledky[0];
        db.query(`
            SELECT k.id, k.text, k.datum_vytvoreni, u.id AS autor_id, u.jmeno, u.prijmeni
            FROM komentare k
            JOIN uzivatele u ON k.autor_id = u.id
            WHERE k.prispevek_id = ?
            ORDER BY k.datum_vytvoreni DESC
        `, [id], (err, komentare) => {
            if (err) return res.status(500).json({ zprava: 'Chyba.' });
            prispevek.komentare = komentare;
            res.status(200).json(prispevek);
        });
    });
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
app.delete('/laiky/:prispevekId', overitPrihlaseni, (req, res) => {
    db.query('DELETE FROM laiky WHERE uzivatel_id = ? AND prispevek_id = ?',
        [req.uzivatel.id, req.params.prispevekId], (err, vysledek) => {
            if (err) return res.status(500).json({ zprava: 'Chyba.' });
            if (vysledek.affectedRows === 0) return res.status(404).json({ zprava: 'Lajk nenalezen.' });
            res.status(200).json({ zprava: 'Lajk odebran.' });
        });
});
app.get('/uzivatele', overitPrihlaseni, (req, res) => {
    db.query('SELECT id, jmeno, prijmeni, vek, pohlavi, profilova_foto, datum_registrace FROM uzivatele ORDER BY prijmeni ASC, jmeno ASC',
        (err, uzivatele) => {
            if (err) return res.status(500).json({ zprava: 'Chyba.' });
            res.status(200).json(uzivatele);
        });
});

app.get('/uzivatele/:id', overitPrihlaseni, (req, res) => {
    const id = req.params.id;
    db.query('SELECT id, jmeno, prijmeni, vek, pohlavi, profilova_foto, datum_registrace FROM uzivatele WHERE id = ?',
        [id], (err, vysledky) => {
            if (err) return res.status(500).json({ zprava: 'Chyba.' });
            if (vysledky.length === 0) return res.status(404).json({ zprava: 'Nenalezen.' });
            const uzivatel = vysledky[0];
            db.query(`
                SELECT p.id, p.nadpis, p.text, p.obrazek, p.datum_vytvoreni,
                    COUNT(DISTINCT l.id) AS pocet_laiku
                FROM prispevky p
                LEFT JOIN laiky l ON p.id = l.prispevek_id
                WHERE p.autor_id = ?
                GROUP BY p.id
                ORDER BY p.datum_vytvoreni DESC
            `, [id], (err, prispevky) => {
                if (err) return res.status(500).json({ zprava: 'Chyba.' });
                db.query(`
                    SELECT DISTINCT p.id, p.nadpis, p.text, p.datum_vytvoreni,
                        u.jmeno AS autor_jmeno, u.prijmeni AS autor_prijmeni
                    FROM prispevky p
                    JOIN uzivatele u ON p.autor_id = u.id
                    LEFT JOIN laiky l ON p.id = l.prispevek_id AND l.uzivatel_id = ?
                    LEFT JOIN komentare k ON p.id = k.prispevek_id AND k.autor_id = ?
                    WHERE (l.uzivatel_id = ? OR k.autor_id = ?) AND p.autor_id != ?
                `, [id, id, id, id, id], (err, ciziPrispevky) => {
                    if (err) return res.status(500).json({ zprava: 'Chyba.' });
                    uzivatel.prispevky = prispevky;
                    uzivatel.aktivita_na_cizich = ciziPrispevky;
                    res.status(200).json(uzivatel);
                });
            });
        });
});
app.listen(port, () => {
    console.log(`Server bezi na portu ${port}`);
});