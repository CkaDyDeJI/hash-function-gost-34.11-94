#include <cstdio>
#include <iostream>

#include "algorithms.h"

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QTextStream>
#include <QDebug>

QTextStream& cout()
{
    static QTextStream out(stdout);
    return out;
}

void output_help()
{
    cout() << "incorrent use of application\n";
    cout() << "usage: " << qAppName() << " [-o out_file] -i in_file\n";
}

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);

    const QCommandLineOption in_option({"i", "input"}, "location to read from <file>", "file", "input.txt");
    const QCommandLineOption out_option({"o", "output"}, "location to write output <file>", "file", "output.txt");

    QCommandLineParser parser;

    parser.addOption(in_option);
    parser.addOption(out_option);

    parser.process(app);

    if (!parser.isSet("i"))
    {
        output_help();
        return EXIT_FAILURE;
    }

    const QString& in_path = qApp->applicationDirPath() + "/" + parser.value("i");
    const QString& out_path = parser.isSet("o") ? (qApp->applicationDirPath() + "/" + parser.value("o")) : (qApp->applicationDirPath() + "/output.txt");

    Algorithms algs(in_path, out_path);

    const bool success = algs.process();

    if (!success)
    {
        cout() << "cannot open input or output files\n";
        return EXIT_FAILURE;
    }
    else
        cout() << "digital signature successfully calculated";

    cout().flush();

    return EXIT_SUCCESS;
}
