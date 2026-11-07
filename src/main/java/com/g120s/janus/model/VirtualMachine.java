package com.g120s.janus.model;

import java.util.*;
public class VirtualMachine {
    public String name, uuid, hostId, mac;
    public String powerState;
    public String guestOs;
    public List<String> nics = new ArrayList<>();  // mac@network
    public String ip;                              // eşleşince dolar
}