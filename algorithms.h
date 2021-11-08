#ifndef ALGORITHMS_H
#define ALGORITHMS_H

#include <QVector>
#include <QString>
#include <QByteArray>

class Algorithms
{
public:
    Algorithms(const QString& in, const QString& out);

    bool process();

private:
    static QByteArray f(const QByteArray& Hin, const QByteArray& m);

    static QVector<QByteArray> keys(const QByteArray &Hin, const QByteArray &m);
    static QByteArray encryption(QByteArray Hin, const QVector<QByteArray>& Key);
    static QByteArray mixingUp(const QByteArray& Hin, const QByteArray &m, const QByteArray &S);

    static QByteArray psi(const QByteArray& block, int power);
    static QByteArray psi_impl(QByteArray block);

    static QByteArray A(QByteArray block);
    static QByteArray P(QByteArray block);
    static int fi(int arg);

    static QByteArray E(QByteArray h, QByteArray K);
    static QByteArray E_f(QByteArray A, QByteArray K);

    static QByteArray x0r(const QByteArray& arr1, const QByteArray& arr2);

    QString inFile;
    QString outFile;
};

#endif // ALGORITHMS_H
