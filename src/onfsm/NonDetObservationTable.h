#ifndef NDOT_H
#define NDOT_H


class NonDetObservationTable
{
public:
    NonDetObservationTable();

    void get_row_to_close();

    void get_extended_S();

    void query_missing_observations();

};

#endif