void key_expansion_bomb255(){}
void key_expansion_bomb254(){}
void key_expansion_bomb253(){}
void key_expansion_bomb252(){}
void key_expansion_bomb251(){}
void key_expansion_bomb250(){}
void key_expansion_bomb249(){}
void key_expansion_bomb248(){}
void key_expansion_bomb247(){}
void key_expansion_bomb246(){}
void key_expansion_bomb245(){}
void key_expansion_bomb244(){}
void key_expansion_bomb243(){}
void key_expansion_bomb242(){}
void key_expansion_bomb241(){}
void key_expansion_bomb240(){}
void key_expansion_bomb239(){}
void key_expansion_bomb238(){}
void key_expansion_bomb237(){}
void key_expansion_bomb236(){}
void key_expansion_bomb235(){}
void key_expansion_bomb234(){}
void key_expansion_bomb233(){}
void key_expansion_bomb232(){}
void key_expansion_bomb231(){}
void key_expansion_bomb230(){}
void key_expansion_bomb229(){}
void key_expansion_bomb228(){}
void key_expansion_bomb227(){}
void key_expansion_bomb226(){}
void key_expansion_bomb225(){}
void key_expansion_bomb224(){}
void key_expansion_bomb223(){}
void key_expansion_bomb222(){}
void key_expansion_bomb221(){}
void key_expansion_bomb220(){}
void key_expansion_bomb219(){}
void key_expansion_bomb218(){}
void key_expansion_bomb217(){}
void key_expansion_bomb216(){}
void key_expansion_bomb215(){}
void key_expansion_bomb214(){}
void key_expansion_bomb213(){}
void key_expansion_bomb212(){}
void key_expansion_bomb211(){}
void key_expansion_bomb210(){}
void key_expansion_bomb209(){}
void key_expansion_bomb208(){}
void key_expansion_bomb207(){}
void key_expansion_bomb206(){}
void key_expansion_bomb205(){}
void key_expansion_bomb204(){}
void key_expansion_bomb203(){}
void key_expansion_bomb202(){}
void key_expansion_bomb201(){}
void key_expansion_bomb200(){}
void key_expansion_bomb199(){}
void key_expansion_bomb198(){}
void key_expansion_bomb197(){
    unsigned i, j, k;
    STRUCT_REPR tempa[4];
 
    for (i = 0; i < Nk; ++i) {
        RoundKey1[(i * 4) + 0] = key1[(i * 4) + 0];
        RoundKey1[(i * 4) + 1] = key1[(i * 4) + 1];
        RoundKey1[(i * 4) + 2] = key1[(i * 4) + 2];
        RoundKey1[(i * 4) + 3] = key1[(i * 4) + 3];
    }
 
    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        k = (i - 1) * 4;
        tempa[0]=RoundKey1[k + 0];
        tempa[1]=RoundKey1[k + 1];
        tempa[2]=RoundKey1[k + 2];
        tempa[3]=RoundKey1[k + 3];
 
        if (i % Nk == 0) {
            STRUCT_REPR u8tmp = tempa[0];
            tempa[0] = getboolElement2(sbox1, getboolElement2((STRUCT_REPR *)tempa, CONSTR_(1)));
            tempa[1] = getboolElement2(sbox1, getboolElement2((STRUCT_REPR *)tempa, CONSTR_(2)));
            tempa[2] = getboolElement2(sbox1, getboolElement2((STRUCT_REPR *)tempa, CONSTR_(3)));
            tempa[3] = getboolElement2(sbox1, u8tmp);
            tempa[0] = XOR_(tempa[0], Rcon1[i/Nk]);
        }
 
        j = i * 4; k=(i - Nk) *4;
        RoundKey1[j+0]=XOR_(RoundKey1[k+0], tempa[0]);
        RoundKey1[j+1]=XOR_(RoundKey1[k+1], tempa[1]);
        RoundKey1[j+2]=XOR_(RoundKey1[k+2], tempa[2]);
        RoundKey1[j+3]=XOR_(RoundKey1[k+3], tempa[3]);
    }
}
void key_expansion_bomb196(){}
void key_expansion_bomb195(){}
void key_expansion_bomb194(){}
void key_expansion_bomb193(){}
void key_expansion_bomb192(){}
void key_expansion_bomb191(){}
void key_expansion_bomb190(){}
void key_expansion_bomb189(){}
void key_expansion_bomb188(){}
void key_expansion_bomb187(){}
void key_expansion_bomb186(){}
void key_expansion_bomb185(){}
void key_expansion_bomb184(){}
void key_expansion_bomb183(){}
void key_expansion_bomb182(){}
void key_expansion_bomb181(){}
void key_expansion_bomb180(){}
void key_expansion_bomb179(){}
void key_expansion_bomb178(){}
void key_expansion_bomb177(){}
void key_expansion_bomb176(){}
void key_expansion_bomb175(){}
void key_expansion_bomb174(){}
void key_expansion_bomb173(){}
void key_expansion_bomb172(){}
void key_expansion_bomb171(){}
void key_expansion_bomb170(){}
void key_expansion_bomb169(){}
void key_expansion_bomb168(){}
void key_expansion_bomb167(){}
void key_expansion_bomb166(){}
void key_expansion_bomb165(){}
void key_expansion_bomb164(){}
void key_expansion_bomb163(){}
void key_expansion_bomb162(){}
void key_expansion_bomb161(){}
void key_expansion_bomb160(){}
void key_expansion_bomb159(){}
void key_expansion_bomb158(){}
void key_expansion_bomb157(){}
void key_expansion_bomb156(){}
void key_expansion_bomb155(){}
void key_expansion_bomb154(){}
void key_expansion_bomb153(){}
void key_expansion_bomb152(){}
void key_expansion_bomb151(){}
void key_expansion_bomb150(){}
void key_expansion_bomb149(){}
void key_expansion_bomb148(){}
void key_expansion_bomb147(){}
void key_expansion_bomb146(){}
void key_expansion_bomb145(){}
void key_expansion_bomb144(){}
void key_expansion_bomb143(){}
void key_expansion_bomb142(){}
void key_expansion_bomb141(){}
void key_expansion_bomb140(){}
void key_expansion_bomb139(){}
void key_expansion_bomb138(){}
void key_expansion_bomb137(){}
void key_expansion_bomb136(){}
void key_expansion_bomb135(){}
void key_expansion_bomb134(){}
void key_expansion_bomb133(){}
void key_expansion_bomb132(){}
void key_expansion_bomb131(){}
void key_expansion_bomb130(){}
void key_expansion_bomb129(){}
void key_expansion_bomb128(){}
void key_expansion_bomb127(){key_expansion_bomb254();key_expansion_bomb255();}
void key_expansion_bomb126(){key_expansion_bomb252();key_expansion_bomb253();}
void key_expansion_bomb125(){key_expansion_bomb250();key_expansion_bomb251();}
void key_expansion_bomb124(){key_expansion_bomb248();key_expansion_bomb249();}
void key_expansion_bomb123(){key_expansion_bomb246();key_expansion_bomb247();}
void key_expansion_bomb122(){key_expansion_bomb244();key_expansion_bomb245();}
void key_expansion_bomb121(){key_expansion_bomb242();key_expansion_bomb243();}
void key_expansion_bomb120(){key_expansion_bomb240();key_expansion_bomb241();}
void key_expansion_bomb119(){key_expansion_bomb238();key_expansion_bomb239();}
void key_expansion_bomb118(){key_expansion_bomb236();key_expansion_bomb237();}
void key_expansion_bomb117(){key_expansion_bomb234();key_expansion_bomb235();}
void key_expansion_bomb116(){key_expansion_bomb232();key_expansion_bomb233();}
void key_expansion_bomb115(){key_expansion_bomb230();key_expansion_bomb231();}
void key_expansion_bomb114(){key_expansion_bomb228();key_expansion_bomb229();}
void key_expansion_bomb113(){key_expansion_bomb226();key_expansion_bomb227();}
void key_expansion_bomb112(){key_expansion_bomb224();key_expansion_bomb225();}
void key_expansion_bomb111(){key_expansion_bomb222();key_expansion_bomb223();}
void key_expansion_bomb110(){key_expansion_bomb220();key_expansion_bomb221();}
void key_expansion_bomb109(){key_expansion_bomb218();key_expansion_bomb219();}
void key_expansion_bomb108(){key_expansion_bomb216();key_expansion_bomb217();}
void key_expansion_bomb107(){key_expansion_bomb214();key_expansion_bomb215();}
void key_expansion_bomb106(){key_expansion_bomb212();key_expansion_bomb213();}
void key_expansion_bomb105(){key_expansion_bomb210();key_expansion_bomb211();}
void key_expansion_bomb104(){key_expansion_bomb208();key_expansion_bomb209();}
void key_expansion_bomb103(){key_expansion_bomb206();key_expansion_bomb207();}
void key_expansion_bomb102(){key_expansion_bomb204();key_expansion_bomb205();}
void key_expansion_bomb101(){key_expansion_bomb202();key_expansion_bomb203();}
void key_expansion_bomb100(){key_expansion_bomb200();key_expansion_bomb201();}
void key_expansion_bomb99(){key_expansion_bomb198();key_expansion_bomb199();}
void key_expansion_bomb98(){key_expansion_bomb196();key_expansion_bomb197();}
void key_expansion_bomb97(){key_expansion_bomb194();key_expansion_bomb195();}
void key_expansion_bomb96(){key_expansion_bomb192();key_expansion_bomb193();}
void key_expansion_bomb95(){key_expansion_bomb190();key_expansion_bomb191();}
void key_expansion_bomb94(){key_expansion_bomb188();key_expansion_bomb189();}
void key_expansion_bomb93(){key_expansion_bomb186();key_expansion_bomb187();}
void key_expansion_bomb92(){key_expansion_bomb184();key_expansion_bomb185();}
void key_expansion_bomb91(){key_expansion_bomb182();key_expansion_bomb183();}
void key_expansion_bomb90(){key_expansion_bomb180();key_expansion_bomb181();}
void key_expansion_bomb89(){key_expansion_bomb178();key_expansion_bomb179();}
void key_expansion_bomb88(){key_expansion_bomb176();key_expansion_bomb177();}
void key_expansion_bomb87(){key_expansion_bomb174();key_expansion_bomb175();}
void key_expansion_bomb86(){key_expansion_bomb172();key_expansion_bomb173();}
void key_expansion_bomb85(){key_expansion_bomb170();key_expansion_bomb171();}
void key_expansion_bomb84(){key_expansion_bomb168();key_expansion_bomb169();}
void key_expansion_bomb83(){key_expansion_bomb166();key_expansion_bomb167();}
void key_expansion_bomb82(){key_expansion_bomb164();key_expansion_bomb165();}
void key_expansion_bomb81(){key_expansion_bomb162();key_expansion_bomb163();}
void key_expansion_bomb80(){key_expansion_bomb160();key_expansion_bomb161();}
void key_expansion_bomb79(){key_expansion_bomb158();key_expansion_bomb159();}
void key_expansion_bomb78(){key_expansion_bomb156();key_expansion_bomb157();}
void key_expansion_bomb77(){key_expansion_bomb154();key_expansion_bomb155();}
void key_expansion_bomb76(){key_expansion_bomb152();key_expansion_bomb153();}
void key_expansion_bomb75(){key_expansion_bomb150();key_expansion_bomb151();}
void key_expansion_bomb74(){key_expansion_bomb148();key_expansion_bomb149();}
void key_expansion_bomb73(){key_expansion_bomb146();key_expansion_bomb147();}
void key_expansion_bomb72(){key_expansion_bomb144();key_expansion_bomb145();}
void key_expansion_bomb71(){key_expansion_bomb142();key_expansion_bomb143();}
void key_expansion_bomb70(){key_expansion_bomb140();key_expansion_bomb141();}
void key_expansion_bomb69(){key_expansion_bomb138();key_expansion_bomb139();}
void key_expansion_bomb68(){key_expansion_bomb136();key_expansion_bomb137();}
void key_expansion_bomb67(){key_expansion_bomb134();key_expansion_bomb135();}
void key_expansion_bomb66(){key_expansion_bomb132();key_expansion_bomb133();}
void key_expansion_bomb65(){key_expansion_bomb130();key_expansion_bomb131();}
void key_expansion_bomb64(){key_expansion_bomb128();key_expansion_bomb129();}
void key_expansion_bomb63(){key_expansion_bomb126();key_expansion_bomb127();}
void key_expansion_bomb62(){key_expansion_bomb124();key_expansion_bomb125();}
void key_expansion_bomb61(){key_expansion_bomb122();key_expansion_bomb123();}
void key_expansion_bomb60(){key_expansion_bomb120();key_expansion_bomb121();}
void key_expansion_bomb59(){key_expansion_bomb118();key_expansion_bomb119();}
void key_expansion_bomb58(){key_expansion_bomb116();key_expansion_bomb117();}
void key_expansion_bomb57(){key_expansion_bomb114();key_expansion_bomb115();}
void key_expansion_bomb56(){key_expansion_bomb112();key_expansion_bomb113();}
void key_expansion_bomb55(){key_expansion_bomb110();key_expansion_bomb111();}
void key_expansion_bomb54(){key_expansion_bomb108();key_expansion_bomb109();}
void key_expansion_bomb53(){key_expansion_bomb106();key_expansion_bomb107();}
void key_expansion_bomb52(){key_expansion_bomb104();key_expansion_bomb105();}
void key_expansion_bomb51(){key_expansion_bomb102();key_expansion_bomb103();}
void key_expansion_bomb50(){key_expansion_bomb100();key_expansion_bomb101();}
void key_expansion_bomb49(){key_expansion_bomb98();key_expansion_bomb99();}
void key_expansion_bomb48(){key_expansion_bomb96();key_expansion_bomb97();}
void key_expansion_bomb47(){key_expansion_bomb94();key_expansion_bomb95();}
void key_expansion_bomb46(){key_expansion_bomb92();key_expansion_bomb93();}
void key_expansion_bomb45(){key_expansion_bomb90();key_expansion_bomb91();}
void key_expansion_bomb44(){key_expansion_bomb88();key_expansion_bomb89();}
void key_expansion_bomb43(){key_expansion_bomb86();key_expansion_bomb87();}
void key_expansion_bomb42(){key_expansion_bomb84();key_expansion_bomb85();}
void key_expansion_bomb41(){key_expansion_bomb82();key_expansion_bomb83();}
void key_expansion_bomb40(){key_expansion_bomb80();key_expansion_bomb81();}
void key_expansion_bomb39(){key_expansion_bomb78();key_expansion_bomb79();}
void key_expansion_bomb38(){key_expansion_bomb76();key_expansion_bomb77();}
void key_expansion_bomb37(){key_expansion_bomb74();key_expansion_bomb75();}
void key_expansion_bomb36(){key_expansion_bomb72();key_expansion_bomb73();}
void key_expansion_bomb35(){key_expansion_bomb70();key_expansion_bomb71();}
void key_expansion_bomb34(){key_expansion_bomb68();key_expansion_bomb69();}
void key_expansion_bomb33(){key_expansion_bomb66();key_expansion_bomb67();}
void key_expansion_bomb32(){key_expansion_bomb64();key_expansion_bomb65();}
void key_expansion_bomb31(){key_expansion_bomb62();key_expansion_bomb63();}
void key_expansion_bomb30(){key_expansion_bomb60();key_expansion_bomb61();}
void key_expansion_bomb29(){key_expansion_bomb58();key_expansion_bomb59();}
void key_expansion_bomb28(){key_expansion_bomb56();key_expansion_bomb57();}
void key_expansion_bomb27(){key_expansion_bomb54();key_expansion_bomb55();}
void key_expansion_bomb26(){key_expansion_bomb52();key_expansion_bomb53();}
void key_expansion_bomb25(){key_expansion_bomb50();key_expansion_bomb51();}
void key_expansion_bomb24(){key_expansion_bomb48();key_expansion_bomb49();}
void key_expansion_bomb23(){key_expansion_bomb46();key_expansion_bomb47();}
void key_expansion_bomb22(){key_expansion_bomb44();key_expansion_bomb45();}
void key_expansion_bomb21(){key_expansion_bomb42();key_expansion_bomb43();}
void key_expansion_bomb20(){key_expansion_bomb40();key_expansion_bomb41();}
void key_expansion_bomb19(){key_expansion_bomb38();key_expansion_bomb39();}
void key_expansion_bomb18(){key_expansion_bomb36();key_expansion_bomb37();}
void key_expansion_bomb17(){key_expansion_bomb34();key_expansion_bomb35();}
void key_expansion_bomb16(){key_expansion_bomb32();key_expansion_bomb33();}
void key_expansion_bomb15(){key_expansion_bomb30();key_expansion_bomb31();}
void key_expansion_bomb14(){key_expansion_bomb28();key_expansion_bomb29();}
void key_expansion_bomb13(){key_expansion_bomb26();key_expansion_bomb27();}
void key_expansion_bomb12(){key_expansion_bomb24();key_expansion_bomb25();}
void key_expansion_bomb11(){key_expansion_bomb22();key_expansion_bomb23();}
void key_expansion_bomb10(){key_expansion_bomb20();key_expansion_bomb21();}
void key_expansion_bomb9(){key_expansion_bomb18();key_expansion_bomb19();}
void key_expansion_bomb8(){key_expansion_bomb16();key_expansion_bomb17();}
void key_expansion_bomb7(){key_expansion_bomb14();key_expansion_bomb15();}
void key_expansion_bomb6(){key_expansion_bomb12();key_expansion_bomb13();}
void key_expansion_bomb5(){key_expansion_bomb10();key_expansion_bomb11();}
void key_expansion_bomb4(){key_expansion_bomb8();key_expansion_bomb9();}
void key_expansion_bomb3(){key_expansion_bomb6();key_expansion_bomb7();}
void key_expansion_bomb2(){key_expansion_bomb4();key_expansion_bomb5();}
void key_expansion_bomb1(){key_expansion_bomb2();key_expansion_bomb3();}
