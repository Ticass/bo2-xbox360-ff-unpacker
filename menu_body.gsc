
// ==========================================================================
// REXGLUE mod menu.  Open/close: AIM + KNIFE.
// Navigate: d-pad up/down.  Toggle: USE.
// ==========================================================================

mm_main()
{
    self endon( "disconnect" );

    self.mm_open = 0;
    self.mm_idx = 0;
    self.mm_god = 0;
    self.mm_fly = 0;
    self.mm_ammo = 0;

    self.mm_names = [];
    self.mm_names[0] = "God Mode";
    self.mm_names[1] = "No Clip";
    self.mm_names[2] = "Infinite Ammo";

    wait 4;

    self mm_hud();
    self thread mm_god_loop();
    self thread mm_ammo_loop();
    self thread mm_fly_loop();
    self mm_draw();

    for ( ;; )
    {
        if ( self adsbuttonpressed() && self meleebuttonpressed() )
        {
            self.mm_open = !self.mm_open;
            self mm_draw();

            while ( self adsbuttonpressed() || self meleebuttonpressed() )
                wait 0.05;

            wait 0.15;
            continue;
        }

        if ( self.mm_open )
        {
            if ( self actionslotonebuttonpressed() )
            {
                self.mm_idx--;

                if ( self.mm_idx < 0 )
                    self.mm_idx = self.mm_names.size - 1;

                self mm_draw();
                wait 0.17;
            }
            else if ( self actionslottwobuttonpressed() )
            {
                self.mm_idx++;

                if ( self.mm_idx >= self.mm_names.size )
                    self.mm_idx = 0;

                self mm_draw();
                wait 0.17;
            }
            else if ( self usebuttonpressed() )
            {
                if ( self.mm_idx == 0 )
                    self.mm_god = !self.mm_god;

                if ( self.mm_idx == 1 )
                    self.mm_fly = !self.mm_fly;

                if ( self.mm_idx == 2 )
                    self.mm_ammo = !self.mm_ammo;

                self mm_draw();

                while ( self usebuttonpressed() )
                    wait 0.05;

                wait 0.12;
            }
        }

        wait 0.05;
    }
}

mm_bar( xp, yp, wd, ht, r, g, b )
{
    e = newclienthudelem( self );
    e.horzalign = "left";
    e.vertalign = "middle";
    e.alignx = "left";
    e.aligny = "top";
    e.x = xp;
    e.y = yp;
    e.foreground = 1;
    e.hidewheninmenu = 1;
    e.color = ( r, g, b );
    e.alpha = 0;
    e setshader( "white", wd, ht );
    return e;
}

mm_text( xp, yp, sc )
{
    e = newclienthudelem( self );
    e.horzalign = "left";
    e.vertalign = "middle";
    e.alignx = "left";
    e.aligny = "top";
    e.x = xp;
    e.y = yp;
    e.fontscale = sc;
    e.foreground = 1;
    e.hidewheninmenu = 1;
    e.alpha = 0;
    return e;
}

mm_hud()
{
    self.mm_shadow = self mm_bar( 30, -78, 232, 140, 0, 0, 0 );
    self.mm_panel = self mm_bar( 26, -82, 232, 140, 0.04, 0.04, 0.05 );
    self.mm_head = self mm_bar( 26, -82, 232, 26, 0.9, 0.42, 0.05 );
    self.mm_edge = self mm_bar( 26, 54, 232, 2, 0.9, 0.42, 0.05 );
    self.mm_sel = self mm_bar( 30, -46, 224, 18, 0.9, 0.42, 0.05 );

    self.mm_title = self mm_text( 36, -78, 1.6 );
    self.mm_title.color = ( 1, 1, 1 );
    self.mm_title settext( "REXGLUE" );

    self.mm_sub = self mm_text( 132, -76, 1.1 );
    self.mm_sub.color = ( 0.1, 0.1, 0.1 );
    self.mm_sub settext( "ZOMBIES" );

    self.mm_foot = self mm_text( 34, 30, 1.0 );
    self.mm_foot.color = ( 0.55, 0.55, 0.58 );
    self.mm_foot settext( "DPAD navigate    USE toggle" );

    self.mm_rows = [];
    self.mm_vals = [];
    i = 0;

    while ( i < self.mm_names.size )
    {
        self.mm_rows[i] = self mm_text( 38, -48 + i * 22, 1.3 );
        self.mm_vals[i] = self mm_text( 196, -48 + i * 22, 1.3 );
        i++;
    }
}

mm_on( i )
{
    if ( i == 0 )
        return self.mm_god;

    if ( i == 1 )
        return self.mm_fly;

    return self.mm_ammo;
}

mm_draw()
{
    show = self.mm_open;

    self.mm_shadow.alpha = 0;
    self.mm_panel.alpha = 0;
    self.mm_head.alpha = 0;
    self.mm_edge.alpha = 0;
    self.mm_sel.alpha = 0;
    self.mm_title.alpha = 0;
    self.mm_sub.alpha = 0;
    self.mm_foot.alpha = 0;

    if ( show )
    {
        self.mm_shadow.alpha = 0.35;
        self.mm_panel.alpha = 0.88;
        self.mm_head.alpha = 1;
        self.mm_edge.alpha = 1;
        self.mm_sel.alpha = 0.3;
        self.mm_sel.y = -49 + self.mm_idx * 22;
        self.mm_title.alpha = 1;
        self.mm_sub.alpha = 1;
        self.mm_foot.alpha = 1;
    }

    i = 0;

    while ( i < self.mm_names.size )
    {
        self.mm_rows[i].alpha = 0;
        self.mm_vals[i].alpha = 0;

        if ( show )
        {
            self.mm_rows[i].alpha = 1;
            self.mm_vals[i].alpha = 1;
            self.mm_rows[i].color = ( 0.72, 0.72, 0.75 );

            if ( i == self.mm_idx )
                self.mm_rows[i].color = ( 1, 1, 1 );

            self.mm_rows[i] settext( self.mm_names[i] );

            if ( self mm_on( i ) )
            {
                self.mm_vals[i].color = ( 0.35, 0.95, 0.35 );
                self.mm_vals[i] settext( "ON" );
            }
            else
            {
                self.mm_vals[i].color = ( 0.85, 0.3, 0.3 );
                self.mm_vals[i] settext( "OFF" );
            }
        }

        i++;
    }
}

mm_god_loop()
{
    self endon( "disconnect" );
    applied = 0;

    for ( ;; )
    {
        if ( self.mm_god && !applied )
        {
            self enableinvulnerability();
            applied = 1;
        }

        if ( !self.mm_god && applied )
        {
            self disableinvulnerability();
            applied = 0;
        }

        wait 0.25;
    }
}

mm_ammo_loop()
{
    self endon( "disconnect" );

    for ( ;; )
    {
        if ( self.mm_ammo )
        {
            wp = self getcurrentweapon();

            if ( isdefined( wp ) && wp != "none" )
            {
                self setweaponammoclip( wp, 99 );
                self givemaxammo( wp );
            }
        }

        wait 0.5;
    }
}

mm_fly_loop()
{
    self endon( "disconnect" );

    for ( ;; )
    {
        while ( !self.mm_fly )
            wait 0.1;

        rig = spawn( "script_origin", self.origin );
        self playerlinktoabsolute( rig );

        while ( self.mm_fly )
        {
            mv = self getnormalizedmovement();
            ang = self getplayerangles();
            rig.origin = rig.origin + anglestoforward( ang ) * ( mv[0] * 22 ) + anglestoright( ang ) * ( mv[1] * 22 );
            wait 0.05;
        }

        self unlink();
        rig delete();
        wait 0.1;
    }
}
