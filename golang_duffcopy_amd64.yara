rule golang_duffcopy_amd64
{
    strings:
        $duffcopy_amd64 = { 0f 10 06 48 83 c6 10 0f 11 07 48 83 c7 10 0f 10 06 48 83 c6 10 0f 11 07 48 83 c7 10 0f 10 06 48 83 c6 10 0f 11 07 48 83 c7 10 0f 10 06 48 83 c6 10 0f 11 07 48 83 c7 10 0f 10 06 48 83 c6 10 0f 11 07 48 83 c7 10 c3 }

    condition:
        $duffcopy_amd64
}

