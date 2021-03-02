struct oui
{
unsigned char prefix[3];
char *vendor;
};
/* 24 bit global prefix */
/* vendor id string */
struct oui oui_table[] = {
{ { 0x00, 0x00, 0x01 }, "XEROX CORPORATION" },
{ { 0x00, 0x00, 0x02 }, "XEROX CORPORATION" },
/* about 5400 lines cut */
{ { 0xAA, 0x00, 0x04 }, "DIGITAL EQUIPMENT CORPORATION" },
{ { 0x00, 0x00, 0x00 }, ""}
};