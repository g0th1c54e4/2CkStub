share_info proto C
StubInit proto C

.CODE
StubEntry PROC

call StubInit
push qword ptr[share_info]
ret

StubEntry ENDP

END