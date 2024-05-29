//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#include <veins/modules/messages/carMessage.h>
carMessage::carMessage() {
    // TODO Auto-generated constructor stub
    pairing_t pairing;
    char param[1024];
    FILE* file = fopen(argv[1], "r");
    size_t count = fread(param, 1, 1024, file);
    fclose(file);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);

    element_init_Zr(pid, pairing);
    element_init_G1(N, pairing);
    element_init_G1(Y_, pairing);
    element_init_G1(E, pairing);
    element_init_G1(Z, pairing);
    element_init_G1(V, pairing);
    element_init_Zr(sigma, pairing);

    timestamp = pbc_get_time();
}

carMessage::~carMessage() {
    // TODO Auto-generated destructor stub

    element_clear(pid);
    element_clear(N);
    element_clear(Y_);
    element_clear(E);
    element_clear(Z);
    element_clear(V);
    element_clear(sigma);
    pairing_clear(pairing);
}

