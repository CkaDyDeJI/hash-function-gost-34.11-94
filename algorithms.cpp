#include "algorithms.h"

#include <QByteArray>
#include <QString>
#include <QFile>
#include <QDebug>

static const char s[] = {
    '\x04', '\x0a', '\x09', '\x02', '\x0d', '\x08', '\x00', '\x0e', '\x06', '\x0b', '\x01', '\x0c', '\x07', '\x0f', '\x05', '\x03',
    '\x0e',	'\x0b',	'\x04',	'\x0c',	'\x06',	'\x0d',	'\x0f',	'\x0a',	'\x02',	'\x03',	'\x08',	'\x01',	'\x00',	'\x07',	'\x05',	'\x09',
    '\x05',	'\x08',	'\x01',	'\x0d',	'\x0a',	'\x03',	'\x04',	'\x02',	'\x0e',	'\x0f',	'\x0c',	'\x07',	'\x06',	'\x00',	'\x09',	'\x0b',
    '\x07',	'\x0d',	'\x0a',	'\x01',	'\x00',	'\x08',	'\x09',	'\x0f',	'\x0e',	'\x04',	'\x06',	'\x0c',	'\x0b',	'\x02',	'\x05',	'\x03',
    '\x06',	'\x0c',	'\x07',	'\x01',	'\x05',	'\x0f',	'\x0d',	'\x08',	'\x04',	'\x0a',	'\x09',	'\x0e',	'\x00',	'\x03',	'\x0b',	'\x02',
    '\x04',	'\x0b',	'\x0a',	'\x00',	'\x07',	'\x02',	'\x01',	'\x0d',	'\x03',	'\x06',	'\x08',	'\x05',	'\x09',	'\x0c',	'\x0f',	'\x0f',
    '\x0d',	'\x0b',	'\x04',	'\x01',	'\x03',	'\x0f',	'\x05',	'\x09',	'\x00',	'\x0a',	'\x0e',	'\x07',	'\x06',	'\x08',	'\x02',	'\x0c',
    '\x01',	'\x0f',	'\x0d',	'\x00',	'\x05',	'\x07',	'\x0a',	'\x04',	'\x09',	'\x02',	'\x03',	'\x0e',	'\x06',	'\x0b',	'\x08',	'\x0c'
};

static const char c3[] = {
    '\xff', '\x00', '\xff', '\xff', '\x00', '\x00', '\x00', '\xff',
    '\xff', '\x00', '\x00', '\xff', '\x00', '\xff', '\xff', '\x00',
    '\x00', '\xff', '\x00', '\xff', '\x00', '\xff', '\x00', '\xff',
    '\xff', '\x00', '\xff', '\x00', '\xff', '\x00', '\xff', '\x00'
};

static QByteArray S (s, 16 * 8);

Algorithms::Algorithms(const QString& in, const QString& out)
    : inFile(in), outFile(out)
{ }

bool Algorithms::process()
{
    QFile in(inFile);

    if (!in.open(QIODevice::ReadOnly))
        return false;

    QByteArray H (32, '\x00');
    QByteArray L (32, '\x00');
    QByteArray Sum (32, '\x00');

    while (!in.atEnd())
    {
        QByteArray chunk = in.read(32);

        if (chunk.size() < 32)
            chunk.append(32 - chunk.size(), '\x00');

        H = f(H, chunk);

        int tmp = 0;
        for (auto i = 0; i < chunk.size(); ++i)
        {
            tmp >>= 8;
            tmp += chunk[i] + Sum[i];

            Sum[i] = tmp & 0xFF;
        }
    }

    auto file_size = in.size();
    in.close();

    for (auto i = 0; i < L.size(); ++i)
    {
        L[i] = file_size & 0xFF;
        file_size >>= 8;
    }

    H = f(f(H, L), Sum);

    QFile out (outFile);

    if (!out.open(QIODevice::WriteOnly))
        return false;

    out.write(H.toHex());
    out.close();

    return true;
}

QByteArray Algorithms::f(const QByteArray &Hin, const QByteArray &m)
{
    const auto keys_v = keys(Hin, m);
    const auto encrypted = encryption(Hin, keys_v);
    const auto mixedUp = mixingUp(Hin, m, encrypted);

    return mixedUp;
}

QVector<QByteArray> Algorithms::keys(const QByteArray &Hin, const QByteArray &m)
{
    QVector<QByteArray> C_s { QByteArray(32, '\x00'), QByteArray(c3, 32), QByteArray(32, '\x00')};
    QVector<QByteArray> K_s(4);

    QByteArray U = Hin;
    QByteArray V = m;
    QByteArray W = x0r(U, V);

    K_s[0] = P(W);

    for (auto i = 1; i < 4; ++i)
    {
        U = x0r(A(U), C_s[i - 1]);
        V = A(A(V));
        W = x0r(U, V);

        K_s[i] = P(W);
    }

    return K_s;
}

QByteArray Algorithms::encryption(QByteArray Hin, const QVector<QByteArray> &Key)
{
    QVector<QByteArray> h_s(4);
    for (auto i = 0; i < 4; ++i)
    {
        h_s[i] = Hin.right(8);
        Hin.chop(8);
    }

    QByteArray result;
    result.resize(32);

    for (auto i = 3; i >= 0; --i)
    {
        const auto tmp = E(h_s[i], Key[3 - i]);

        for (auto j = 0; j < 8; ++j)
        {
            result[i * 8 + j] = tmp[i];
        }
    }

    return result;
}

QByteArray Algorithms::mixingUp(const QByteArray &Hin, const QByteArray& m, const QByteArray& S)
{
    return psi(x0r(Hin, psi(x0r(m, psi(S, 12)), 1)), 61);
}

QByteArray Algorithms::psi(const QByteArray &block, int power)
{
    QByteArray temp = block;
    while (power--)
    {
        temp = psi_impl(temp);
    }

    return temp;
}

QByteArray Algorithms::psi_impl(QByteArray block)
{
    QVector<QByteArray> y_s(16);
    for (auto i = 15; i >= 0; --i)
    {
        y_s[i] = block.right(2);
        block.chop(2);
    }

    QByteArray result = x0r(x0r(x0r(x0r(x0r(y_s[0], y_s[1]), y_s[2]), y_s[3]), y_s[12]), y_s[15]);
    result.resize(32);

    for (auto i = 1; i < 16; ++i)
    {
        result[i * 2] = y_s[i][0];
        result[i * 2 + 1] = y_s[i][1];
    }

    return result;
}

QByteArray Algorithms::A(QByteArray block)
{
    QVector<QByteArray> y_s(4);
    for (auto i = 3; i >= 0; --i)
    {
        y_s[i] = block.right(8);
        block.chop(8);
    }

    QByteArray result = x0r(y_s[0], y_s[1]);

    result.resize(32);
    for (auto i = 3; i >= 1; --i)
        for (auto j = 0; j < y_s[i].size(); ++j)
            result[(4 - i) * 8 + j] = y_s[i][j];

    return result;
}

QByteArray Algorithms::P(QByteArray block)
{
    QVector<QByteArray> y_s(32);
    for (auto i = 31; i >= 0; --i)
    {
        y_s[i] = block.right(1);
        block.chop(1);
    }

    QByteArray res;
    res.resize(32);

    for (auto i = 0; i < 32; ++i)
        res[i] = y_s[fi(i)][0];

    return res;
}

int Algorithms::fi(int arg)
{
    int k = ((arg - 1) >> 2) + 1;

    int i = arg - 1 - ((k - 1) << 2);

    return (i << 3) + k;
}

QByteArray Algorithms::E(QByteArray h, QByteArray K)
{
    QByteArray A, B;
    A.resize(4);
    B.resize(4);

    for (int i = 0; i < 4; i++)
        A[i] = h[i];
    for (int i = 0; i < 4; i++)
        B[i] = h[i + 4];

    for (auto step = 0; step < 3; ++step)
    {
        for (auto i = 0; i < 32; i += 4)
        {
            QByteArray tmp = E_f(A, K.sliced(i));

            for (int i = 0; i < 4; ++i)
                tmp[i] ^= B[i];

            B = A;
            A = tmp;
        }
    }

    for (int i = 28; i >= 0; i -= 4)
    {
        QByteArray tmp = E_f(A, K.sliced(i));

        for (int i = 0; i < 4; ++i)
            tmp[i] ^= B[i];

        B = A;
        A = tmp;
    }

    QByteArray result;
    result.resize(8);

    for (int i = 0; i < 4; ++i)
    {
        result[i] = B[i];
        result[i + 4] = A[i];
    }

    return result;
}

QByteArray Algorithms::E_f(QByteArray A, QByteArray K)
{
    QByteArray R;
    R.resize(4);

    int c = 0;
    for (int i = 0; i < 4; ++i)
    {
        c += A[i] + K[i];
        R[i] = c & 0xFF;
        c >>= 8;
    }

    for (int i = 0; i < 8; i++)
    {
        int x = R[i >> 1] & ((i & 1) ? 0xF0 : 0x0F);
        R[i >> 1] ^= x;
        x >>= (i & 1) ? 4 : 0;
        x = S[i * 8 + x];
        R[i >> 1] |= x << ((i & 1) ? 4 : 0);
    }

    auto tmp = R[3];
    R[3] = R[2];
    R[2] = R[1];
    R[1] = R[0];
    R[0] = tmp;

    tmp = R[0] >> 5;

    for (int i = 1; i < 4; i++)
    {
        int nTmp = R[i] >> 5;
        R[i] = (R[i] << 3) | tmp;
        tmp = nTmp;
    }

    R[0] = (R[0] << 3) | tmp;

    return R;
}

QByteArray Algorithms::x0r(const QByteArray& arr1, const QByteArray& arr2)
{
    QByteArray result;
    result.resize(arr1.size());

    for (auto i = 0; i < arr1.size(); ++i)
        result[i] = arr1[i] ^ arr2[i];

    return result;
}
