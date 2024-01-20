share_info proto C
StubInit proto C

.CODE
StubEntry PROC

sub rsp, 28h
call StubInit
add rsp, 28h
push qword ptr[share_info]
ret

StubEntry ENDP

END