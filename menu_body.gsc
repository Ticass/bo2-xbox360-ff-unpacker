
// ==========================================================================
// Cry's Recomp Menu -- Zombies mod menu for the ReXGlue BO2 recompilation.
//
// Threaded from codecallback_playerconnect in maps/mp/gametypes_zm/_callbacksetup.gsc.
//
//   AIM + KNIFE       open / close
//   DPAD UP / DOWN    move within the tab
//   DPAD LEFT / RIGHT switch tab
//   USE               select / toggle
//
// Every cross-script call is fully qualified.  _callbacksetup only includes
// _hostmigration, _globallogic*, maps/mp/_audio and maps/mp/_utility, so anything
// out of common_scripts/utility or maps/mp/zombies/* has to name its own script or
// the import will not resolve at link time.
//
// Every builtin used here was checked against the engine's builtin-name table in
// the XEX before it was written, not assumed.
//
// Colours are the Quebec flag: azure blue and white.
// ==========================================================================

mm_main()
{
    self endon( "disconnect" );

    self.mm_open = 0;
    self.mm_tab = 0;
    self.mm_idx = 0;
    self.mm_top = 0;
    self.mm_max = 9;
    self.mm_accent = 0;

    self.mm_on = [];
    self.mm_on["god"] = 0;
    self.mm_on["nodeath"] = 0;
    self.mm_on["ammo"] = 0;
    self.mm_on["fly"] = 0;
    self.mm_on["speed"] = 0;
    self.mm_on["jump"] = 0;
    self.mm_on["gravity"] = 0;
    self.mm_on["ignore"] = 0;
    self.mm_on["third"] = 0;
    self.mm_on["points"] = 0;
    self.mm_on["instakill"] = 0;
    self.mm_on["freeze"] = 0;
    self.mm_on["slowmo"] = 0;
    self.mm_on["closeonsel"] = 0;

    mm_build_tables();
    mm_install_oob_hook();

    wait 4;

    self mm_hud();
    self thread mm_god_loop();
    self thread mm_ammo_loop();
    self thread mm_fly_loop();
    self thread mm_points_loop();
    self thread mm_zombie_loop();

    self mm_tab_build();
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
                self mm_move( -1 );
                wait 0.16;
            }
            else if ( self actionslottwobuttonpressed() )
            {
                self mm_move( 1 );
                wait 0.16;
            }
            else if ( self actionslotthreebuttonpressed() )
            {
                self mm_switch_tab( -1 );
                wait 0.18;
            }
            else if ( self actionslotfourbuttonpressed() )
            {
                self mm_switch_tab( 1 );
                wait 0.18;
            }
            else if ( self usebuttonpressed() )
            {
                self mm_select();

                while ( self usebuttonpressed() )
                    wait 0.05;

                wait 0.12;
            }
        }

        wait 0.05;
    }
}

// --------------------------------------------------------------------------
// Shared tables.  Level scope so they are built once no matter how many players
// connect.
// --------------------------------------------------------------------------

mm_build_tables()
{
    if ( isdefined( level.mm_tabs ) )
        return;

    tabs = [];
    tabs[0] = "PLAYER";
    tabs[1] = "WEAPONS";
    tabs[2] = "POINTS";
    tabs[3] = "PERKS";
    tabs[4] = "FUN";
    tabs[5] = "GAME";
    tabs[6] = "MAP";
    tabs[7] = "SETTINGS";
    level.mm_tabs = tabs;

    ids = [];
    names = [];
    ids[0] = "specialty_armorvest";
    names[0] = "Juggernog";
    ids[1] = "specialty_quickrevive";
    names[1] = "Quick Revive";
    ids[2] = "specialty_fastreload";
    names[2] = "Speed Cola";
    ids[3] = "specialty_rof";
    names[3] = "Double Tap";
    ids[4] = "specialty_longersprint";
    names[4] = "Stamin-Up";
    ids[5] = "specialty_deadshot";
    names[5] = "Deadshot Daiquiri";
    ids[6] = "specialty_additionalprimaryweapon";
    names[6] = "Mule Kick";
    ids[7] = "specialty_flakjacket";
    names[7] = "PhD Flopper";
    ids[8] = "specialty_scavenger";
    names[8] = "Tombstone";
    ids[9] = "specialty_finalstand";
    names[9] = "Whos Who";
    ids[10] = "specialty_grenadepulldeath";
    names[10] = "Electric Cherry";
    level.mm_perk_ids = ids;
    level.mm_perk_names = names;

    // Quebec first, then a few alternates the settings tab can cycle through.
    acc = [];
    accn = [];
    acc[0] = ( 0.04, 0.29, 0.62 );
    accn[0] = "Quebec Blue";
    acc[1] = ( 0.93, 0.93, 0.96 );
    accn[1] = "Fleur White";
    acc[2] = ( 0.85, 0.68, 0.13 );
    accn[2] = "Gold";
    acc[3] = ( 0.75, 0.13, 0.16 );
    accn[3] = "Rouge";
    level.mm_accents = acc;
    level.mm_accent_names = accn;
}

// _zm::player_out_of_playable_area_monitor kills the player when they are in a
// kill brush or outside the playable area, but it asks
// level.player_out_of_playable_area_monitor_callback for permission first and
// skips the kill when that returns false.  Chaining onto whatever the map already
// installed keeps map logic (Moon's no-atmosphere handling, for one) intact.
mm_install_oob_hook()
{
    if ( isdefined( level.mm_oob_installed ) )
        return;

    level.mm_oob_installed = 1;
    level.mm_oob_prev = level.player_out_of_playable_area_monitor_callback;
    level.player_out_of_playable_area_monitor_callback = ::mm_oob_check;
}

mm_oob_check()
{
    if ( isdefined( self.mm_on ) && isdefined( self.mm_on["nodeath"] ) && self.mm_on["nodeath"] )
        return 0;

    if ( isdefined( level.mm_oob_prev ) )
        return self [[ level.mm_oob_prev ]]();

    return 1;
}

// --------------------------------------------------------------------------
// Tab contents.  Rebuilt every time a tab is entered so rows can reflect live
// level state.
// --------------------------------------------------------------------------

mm_row( label, id, key, arg )
{
    i = self.mm_names.size;
    self.mm_names[i] = label;
    self.mm_ids[i] = id;
    self.mm_keys[i] = key;
    self.mm_args[i] = arg;
}

mm_tab_build()
{
    self.mm_names = [];
    self.mm_ids = [];
    self.mm_keys = [];
    self.mm_args = [];

    switch ( self.mm_tab )
    {
        case 0:
            self mm_row( "God Mode", 1, "god", "" );
            self mm_row( "Disable Death Barriers", 2, "nodeath", "" );
            self mm_row( "Infinite Ammo", 3, "ammo", "" );
            self mm_row( "No Clip", 4, "fly", "" );
            self mm_row( "Super Speed", 5, "speed", "" );
            self mm_row( "Super Jump", 6, "jump", "" );
            self mm_row( "Low Gravity", 7, "gravity", "" );
            self mm_row( "Zombies Ignore Me", 8, "ignore", "" );
            self mm_row( "Third Person", 9, "third", "" );
            self mm_row( "Teleport To Crosshair", 10, "", "" );
            self mm_row( "Refill Health", 11, "", "" );
            break;
        case 1:
            self mm_row( "Pack-A-Punch Current", 20, "", "" );
            self mm_row( "Pack-A-Punch All", 21, "", "" );
            self mm_row( "Max Ammo", 22, "", "" );
            self mm_row( "Random Box Weapon", 23, "", "" );
            self mm_row( "Random Upgraded Weapon", 24, "", "" );
            self mm_row( "Drop Fire Sale", 25, "", "" );
            break;
        case 2:
            self mm_row( "Infinite Points", 40, "points", "" );
            self mm_row( "Give 10,000", 41, "", "" );
            self mm_row( "Give 100,000", 42, "", "" );
            self mm_row( "Give 1,000,000", 43, "", "" );
            self mm_row( "Reset To 500", 44, "", "" );
            self mm_row( "Drop Double Points", 45, "", "" );
            break;
        case 3:
            self mm_row( "Give All Perks", 60, "", "" );
            i = 0;

            while ( i < level.mm_perk_ids.size )
            {
                self mm_row( level.mm_perk_names[i], 61, "", level.mm_perk_ids[i] );
                i++;
            }

            break;
        case 4:
            self mm_row( "Drop Nuke", 80, "", "nuke" );
            self mm_row( "Drop Insta-Kill", 80, "", "insta_kill" );
            self mm_row( "Drop Max Ammo", 80, "", "full_ammo" );
            self mm_row( "Drop Double Points", 80, "", "double_points" );
            self mm_row( "Drop Carpenter", 80, "", "carpenter" );
            self mm_row( "Drop Fire Sale", 80, "", "fire_sale" );
            self mm_row( "Drop Free Perk", 80, "", "free_perk" );
            self mm_row( "Slow Motion", 81, "slowmo", "" );
            self mm_row( "Freeze Zombies", 82, "freeze", "" );
            break;
        case 5:
            self mm_row( "Skip Round", 100, "", "" );
            self mm_row( "Skip 5 Rounds", 101, "", "" );
            self mm_row( "Kill All Zombies", 102, "", "" );
            self mm_row( "Instant Kill", 103, "instakill", "" );
            break;
        case 6:
            self mm_row( "Open All Doors", 120, "", "" );
            self mm_row( "Turn On Power", 121, "", "" );
            self mm_row( "Open All Barriers", 122, "", "" );
            break;
        default:
            self mm_row( "Accent Colour", 140, "", "" );
            self mm_row( "Rows Shown", 141, "", "" );
            self mm_row( "Close On Select", 142, "closeonsel", "" );
            self mm_row( "Reset All Cheats", 143, "", "" );
            break;
    }
}

mm_switch_tab( dir )
{
    self.mm_tab = self.mm_tab + dir;

    if ( self.mm_tab < 0 )
        self.mm_tab = level.mm_tabs.size - 1;

    if ( self.mm_tab >= level.mm_tabs.size )
        self.mm_tab = 0;

    self.mm_idx = 0;
    self.mm_top = 0;
    self mm_tab_build();
    self mm_draw();
}

mm_move( dir )
{
    self.mm_idx = self.mm_idx + dir;

    if ( self.mm_idx < 0 )
        self.mm_idx = self.mm_names.size - 1;

    if ( self.mm_idx >= self.mm_names.size )
        self.mm_idx = 0;

    if ( self.mm_idx < self.mm_top )
        self.mm_top = self.mm_idx;

    if ( self.mm_idx >= self.mm_top + self.mm_max )
        self.mm_top = self.mm_idx - self.mm_max + 1;

    self mm_draw();
}

mm_select()
{
    id = self.mm_ids[self.mm_idx];
    key = self.mm_keys[self.mm_idx];
    arg = self.mm_args[self.mm_idx];

    if ( key != "" )
    {
        self.mm_on[key] = !self.mm_on[key];
        self mm_apply_toggle( key );
        self mm_after_select();
        return;
    }

    switch ( id )
    {
        case 10:
            self mm_teleport();
            break;
        case 11:
            self.health = self.maxhealth;
            break;
        case 20:
            self mm_pack_current();
            break;
        case 21:
            self thread mm_pack_all();
            break;
        case 22:
            self mm_max_ammo();
            break;
        case 23:
            self mm_random_weapon( 0 );
            break;
        case 24:
            self thread mm_random_weapon( 1 );
            break;
        case 25:
            self mm_drop_powerup( "fire_sale" );
            break;
        case 41:
            self mm_give_points( 10000 );
            break;
        case 42:
            self mm_give_points( 100000 );
            break;
        case 43:
            self mm_give_points( 1000000 );
            break;
        case 44:
            self mm_set_points( 500 );
            break;
        case 45:
            self mm_drop_powerup( "double_points" );
            break;
        case 60:
            self thread mm_give_all_perks();
            break;
        case 61:
            self thread mm_give_one_perk( arg );
            break;
        case 80:
            self mm_drop_powerup( arg );
            break;
        case 100:
            self thread mm_skip_rounds( 1 );
            break;
        case 101:
            self thread mm_skip_rounds( 5 );
            break;
        case 102:
            self mm_kill_zombies();
            break;
        case 120:
            self thread mm_open_all_doors();
            break;
        case 121:
            self mm_power_on();
            break;
        case 122:
            self mm_open_barriers();
            break;
        case 140:
            self mm_cycle_accent();
            break;
        case 141:
            self mm_cycle_rows();
            break;
        case 143:
            self mm_reset_all();
            break;
        default:
            break;
    }

    self mm_after_select();
}

mm_after_select()
{
    if ( self.mm_on["closeonsel"] && self.mm_ids[self.mm_idx] != 142 )
    {
        self.mm_open = 0;
        self mm_draw();
        return;
    }

    self mm_draw();
}

mm_apply_toggle( key )
{
    if ( key == "speed" )
    {
        if ( self.mm_on["speed"] )
            self setmovespeedscale( 2 );
        else
            self setmovespeedscale( 1 );

        return;
    }

    // jump_height, bg_gravity and timescale are level dvars -- these three affect
    // everyone in the game, not just the player who toggled them.
    if ( key == "jump" )
    {
        if ( self.mm_on["jump"] )
            setdvar( "jump_height", 250 );
        else
            setdvar( "jump_height", 39 );

        return;
    }

    if ( key == "gravity" )
    {
        if ( self.mm_on["gravity"] )
            setdvar( "bg_gravity", 200 );
        else
            setdvar( "bg_gravity", 800 );

        return;
    }

    if ( key == "slowmo" )
    {
        if ( self.mm_on["slowmo"] )
            setdvar( "timescale", 0.4 );
        else
            setdvar( "timescale", 1 );

        return;
    }

    if ( key == "ignore" )
    {
        self.ignoreme = self.mm_on["ignore"];
        return;
    }

    if ( key == "third" )
        self setclientthirdperson( self.mm_on["third"] );
}

// --------------------------------------------------------------------------
// HUD
// --------------------------------------------------------------------------

mm_bar( xp, yp, wd, ht, col )
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
    e.color = col;
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
    black = ( 0, 0, 0 );
    panel = ( 0.03, 0.04, 0.08 );
    white = ( 1, 1, 1 );

    self.mm_shadow = self mm_bar( 30, -126, 320, 312, black );
    self.mm_panel = self mm_bar( 26, -130, 320, 312, panel );
    self.mm_head = self mm_bar( 26, -130, 320, 28, black );
    self.mm_tabbar = self mm_bar( 26, -102, 320, 22, black );
    self.mm_edge = self mm_bar( 26, 146, 320, 2, black );
    self.mm_sel = self mm_bar( 30, -77, 312, 18, black );

    self.mm_title = self mm_text( 36, -126, 1.7 );
    self.mm_title.color = white;
    self.mm_title settext( "CRY'S RECOMP MENU" );

    self.mm_tabname = self mm_text( 40, -100, 1.3 );
    self.mm_tabcount = self mm_text( 292, -100, 1.1 );

    self.mm_foot = self mm_text( 34, 152, 0.95 );
    self.mm_foot.color = ( 0.55, 0.57, 0.62 );
    self.mm_foot settext( "UP/DOWN move   LEFT/RIGHT tab   USE select" );

    self.mm_rowe = [];
    self.mm_vale = [];
    i = 0;

    while ( i < 11 )
    {
        self.mm_rowe[i] = self mm_text( 40, -76 + i * 22, 1.3 );
        self.mm_vale[i] = self mm_text( 262, -76 + i * 22, 1.3 );
        i++;
    }

    self mm_layout();
}

// Resize the frame to whatever row count the settings tab is asking for.
mm_layout()
{
    bottom = -78 + self.mm_max * 22;
    height = bottom + 24 + 130;

    self.mm_shadow setshader( "white", 320, height );
    self.mm_panel setshader( "white", 320, height );
    self.mm_edge.y = bottom + 4;
    self.mm_foot.y = bottom + 10;
}

mm_accent()
{
    return level.mm_accents[self.mm_accent];
}

mm_value_text( i )
{
    key = self.mm_keys[i];

    if ( key != "" )
    {
        if ( self.mm_on[key] )
            return "ON";

        return "OFF";
    }

    if ( self.mm_ids[i] == 140 )
        return level.mm_accent_names[self.mm_accent];

    if ( self.mm_ids[i] == 141 )
        return "" + self.mm_max;

    return "";
}

mm_draw()
{
    show = self.mm_open;
    accent = self mm_accent();

    self.mm_head.color = accent;
    self.mm_edge.color = accent;
    self.mm_sel.color = accent;
    self.mm_tabname.color = accent;
    self.mm_tabbar.color = ( 0.07, 0.09, 0.14 );

    self.mm_shadow.alpha = 0;
    self.mm_panel.alpha = 0;
    self.mm_head.alpha = 0;
    self.mm_tabbar.alpha = 0;
    self.mm_edge.alpha = 0;
    self.mm_sel.alpha = 0;
    self.mm_title.alpha = 0;
    self.mm_tabname.alpha = 0;
    self.mm_tabcount.alpha = 0;
    self.mm_foot.alpha = 0;

    if ( show )
    {
        self.mm_shadow.alpha = 0.4;
        self.mm_panel.alpha = 0.9;
        self.mm_head.alpha = 1;
        self.mm_tabbar.alpha = 1;
        self.mm_edge.alpha = 1;
        self.mm_sel.alpha = 0.35;
        self.mm_sel.y = -77 + ( self.mm_idx - self.mm_top ) * 22;
        self.mm_title.alpha = 1;
        self.mm_tabname.alpha = 1;
        self.mm_tabname settext( "< " + level.mm_tabs[self.mm_tab] + " >" );
        self.mm_tabcount.alpha = 1;
        self.mm_tabcount.color = ( 0.5, 0.52, 0.58 );
        self.mm_tabcount settext( ( self.mm_tab + 1 ) + "/" + level.mm_tabs.size );
        self.mm_foot.alpha = 1;
    }

    i = 0;

    while ( i < 11 )
    {
        self.mm_rowe[i].alpha = 0;
        self.mm_vale[i].alpha = 0;
        row = self.mm_top + i;

        if ( show && i < self.mm_max && row < self.mm_names.size )
        {
            self.mm_rowe[i].alpha = 1;
            self.mm_rowe[i].color = ( 0.74, 0.76, 0.8 );

            if ( row == self.mm_idx )
                self.mm_rowe[i].color = ( 1, 1, 1 );

            self.mm_rowe[i] settext( self.mm_names[row] );
            txt = self mm_value_text( row );

            if ( txt != "" )
            {
                self.mm_vale[i].alpha = 1;
                self.mm_vale[i].color = ( 0.62, 0.64, 0.7 );

                if ( txt == "ON" )
                    self.mm_vale[i].color = ( 0.35, 0.95, 0.45 );

                if ( txt == "OFF" )
                    self.mm_vale[i].color = ( 0.8, 0.32, 0.32 );

                self.mm_vale[i] settext( txt );
            }
        }

        i++;
    }
}

// --------------------------------------------------------------------------
// Background loops
// --------------------------------------------------------------------------

mm_god_loop()
{
    self endon( "disconnect" );
    applied = 0;

    for ( ;; )
    {
        if ( self.mm_on["god"] && !applied )
        {
            self enableinvulnerability();
            applied = 1;
        }

        if ( !self.mm_on["god"] && applied )
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
        if ( self.mm_on["ammo"] )
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

// No Clip.
//
// The previous version linked to a bare spawn( "script_origin" ) and had no
// vertical axis.  Two things were wrong with that: every other link site in the
// shipped scripts uses a script_model wearing "tag_origin" (precached by
// _globallogic::init on every ZM map), and Zombies runs close enough to the entity
// cap that a raw spawn can hand back undefined -- after which playerlinktoabsolute
// is being passed nothing and the whole thread dies silently, which is exactly
// what "no clip does nothing" looks like.
//
// So: spawn the model form, check it, and fall back to moving the player directly
// with setorigin if the entity could not be created.  Jump and crouch give the
// vertical axis.
mm_fly_loop()
{
    self endon( "disconnect" );

    for ( ;; )
    {
        while ( !self.mm_on["fly"] )
            wait 0.1;

        rig = spawn( "script_model", self.origin );

        if ( isdefined( rig ) )
        {
            rig setmodel( "tag_origin" );
            self playerlinktoabsolute( rig );

            while ( self.mm_on["fly"] )
            {
                rig.origin = rig.origin + self mm_fly_step();
                wait 0.05;
            }

            self unlink();
            rig delete();
        }
        else
        {
            while ( self.mm_on["fly"] )
            {
                self setorigin( self.origin + self mm_fly_step() );
                wait 0.05;
            }
        }

        wait 0.1;
    }
}

mm_fly_step()
{
    mv = self getnormalizedmovement();
    ang = self getplayerangles();
    move = anglestoforward( ang ) * ( mv[0] * 30 ) + anglestoright( ang ) * ( mv[1] * 30 );

    if ( self jumpbuttonpressed() )
        move = move + vectorscale( ( 0, 0, 1 ), 30.0 );

    if ( self stancebuttonpressed() )
        move = move + vectorscale( ( 0, 0, -1 ), 30.0 );

    return move;
}

// Topping the score up rather than writing self.score directly keeps
// self.pers["score"] and the score HUD in step with it.
mm_points_loop()
{
    self endon( "disconnect" );

    for ( ;; )
    {
        if ( self.mm_on["points"] && isdefined( self.score ) && self.score < 500000 )
            self maps\mp\zombies\_zm_score::add_to_player_score( 1000000 - self.score, 0 );

        wait 1;
    }
}

// One walk of the round's AI list serves both instant-kill and freeze, so the
// zombie array is only fetched once per tick instead of once per feature.
mm_zombie_loop()
{
    self endon( "disconnect" );

    for ( ;; )
    {
        if ( self.mm_on["instakill"] || self.mm_on["freeze"] )
        {
            zombies = maps\mp\zombies\_zm_utility::get_round_enemy_array();
            i = 0;

            while ( i < zombies.size )
            {
                z = zombies[i];

                if ( isdefined( z ) && isalive( z ) )
                {
                    if ( self.mm_on["instakill"] && z.health > 1 )
                        z.health = 1;

                    if ( self.mm_on["freeze"] )
                        z setgoalpos( z.origin );
                }

                i++;
            }
        }

        wait 0.5;
    }
}

// --------------------------------------------------------------------------
// Player
// --------------------------------------------------------------------------

mm_teleport()
{
    eye = self geteye();
    ang = self getplayerangles();
    end = eye + anglestoforward( ang ) * 100000;
    trace = bullettrace( eye, end, 0, self );

    if ( isdefined( trace["position"] ) )
        self setorigin( trace["position"] + vectorscale( ( 0, 0, 1 ), 12.0 ) );
}

// --------------------------------------------------------------------------
// Points
// --------------------------------------------------------------------------

mm_give_points( amount )
{
    self maps\mp\zombies\_zm_score::add_to_player_score( amount, 0 );
}

mm_set_points( amount )
{
    if ( !isdefined( self.score ) )
        return;

    if ( self.score > amount )
    {
        self maps\mp\zombies\_zm_score::minus_to_player_score( self.score - amount );
        return;
    }

    self maps\mp\zombies\_zm_score::add_to_player_score( amount - self.score, 0 );
}

// --------------------------------------------------------------------------
// Perks.  give_perk walks level._custom_perks, which only exists once
// _zm_perks::init has run -- it does not on a map with magic disabled.
// --------------------------------------------------------------------------

mm_perks_ready()
{
    if ( !isdefined( level._custom_perks ) )
        return 0;

    return 1;
}

mm_give_one_perk( perk )
{
    self endon( "disconnect" );

    if ( !self mm_perks_ready() )
        return;

    if ( self maps\mp\zombies\_zm_perks::check_player_has_perk( perk ) )
        return;

    self maps\mp\zombies\_zm_perks::give_perk( perk, 0 );
}

mm_give_all_perks()
{
    self endon( "disconnect" );

    if ( !self mm_perks_ready() )
        return;

    i = 0;

    while ( i < level.mm_perk_ids.size )
    {
        perk = level.mm_perk_ids[i];

        if ( !self maps\mp\zombies\_zm_perks::check_player_has_perk( perk ) )
            self maps\mp\zombies\_zm_perks::give_perk( perk, 0 );

        i++;
        wait 0.1;
    }
}

// --------------------------------------------------------------------------
// Weapons
// --------------------------------------------------------------------------

mm_upgrade( current )
{
    if ( !isdefined( current ) || current == "none" )
        return;

    if ( !self maps\mp\zombies\_zm_weapons::can_upgrade_weapon( current ) )
        return;

    upgrade = self maps\mp\zombies\_zm_weapons::get_upgrade_weapon( current, 1 );

    if ( !isdefined( upgrade ) || upgrade == current )
        return;

    options = self maps\mp\zombies\_zm_weapons::get_pack_a_punch_weapon_options( upgrade );
    self takeweapon( current );
    self giveweapon( upgrade, 0, options );
    self givemaxammo( upgrade );
    self switchtoweapon( upgrade );
}

mm_pack_current()
{
    self mm_upgrade( self getcurrentweapon() );
}

mm_pack_all()
{
    self endon( "disconnect" );
    weapons = self getweaponslistprimaries();
    i = 0;

    while ( i < weapons.size )
    {
        self mm_upgrade( weapons[i] );
        i++;
        wait 0.25;
    }
}

mm_max_ammo()
{
    weapons = self getweaponslistprimaries();
    i = 0;

    while ( i < weapons.size )
    {
        self givemaxammo( weapons[i] );
        self setweaponammoclip( weapons[i], 99 );
        i++;
    }
}

// Drawn from the map's own box table, so this can never hand out a weapon the
// zone did not precache.
mm_random_weapon( upgraded )
{
    self endon( "disconnect" );

    if ( !isdefined( level.zombie_weapons ) )
        return;

    keys = getarraykeys( level.zombie_weapons );

    if ( !isdefined( keys ) || keys.size < 1 )
        return;

    pick = keys[randomint( keys.size )];
    self maps\mp\zombies\_zm_weapons::weapon_give( pick, 0, 0 );

    if ( upgraded )
    {
        wait 0.1;
        self mm_upgrade( pick );
    }
}

// --------------------------------------------------------------------------
// Powerups
// --------------------------------------------------------------------------

mm_drop_powerup( name )
{
    if ( !isdefined( level.zombie_powerups ) || !isdefined( level.zombie_powerups[name] ) )
        return;

    maps\mp\zombies\_zm_powerups::specific_powerup_drop( name, self.origin );
}

// --------------------------------------------------------------------------
// Game
// --------------------------------------------------------------------------

// round_wait polls `get_current_zombie_count() > 0 || level.zombie_total > 0`, so
// emptying both ends the round within a second through the normal round_over path.
// Setting the end_round_wait flag would be quicker but nothing ever clears it
// again, which would end every later round instantly too.
mm_skip_rounds( count )
{
    self endon( "disconnect" );
    i = 0;

    while ( i < count )
    {
        level.zombie_total = 0;
        self mm_kill_zombies();
        i++;
        wait 6;
    }
}

mm_kill_zombies()
{
    zombies = maps\mp\zombies\_zm_utility::get_round_enemy_array();
    i = 0;

    while ( i < zombies.size )
    {
        if ( isdefined( zombies[i] ) && isalive( zombies[i] ) )
            zombies[i] dodamage( zombies[i].health + 1000, zombies[i].origin );

        i++;
    }
}

// --------------------------------------------------------------------------
// Map
// --------------------------------------------------------------------------

// door_buy and debris_think both treat a "trigger" notify whose second argument
// is true as a forced, free purchase -- the same path the quantum bomb uses.
mm_open_all_doors()
{
    self endon( "disconnect" );

    self mm_power_on();
    wait 0.5;

    self mm_open_group( "zombie_door" );
    self mm_open_group( "zombie_debris" );
    self mm_open_group( "zombie_airlock_buy" );
}

mm_open_group( name )
{
    ents = getentarray( name, "targetname" );
    i = 0;

    while ( i < ents.size )
    {
        if ( isdefined( ents[i] ) )
            ents[i] notify( "trigger", self, 1 );

        i++;
        wait 0.1;
    }
}

mm_power_on()
{
    if ( common_scripts\utility::flag_exists( "power_on" ) && !common_scripts\utility::flag( "power_on" ) )
        common_scripts\utility::flag_set( "power_on" );

    maps\mp\zombies\_zm_power::set_global_power( 1 );
}

mm_open_barriers()
{
    if ( !isdefined( level.exterior_goals ) )
        return;

    maps\mp\zombies\_zm_blockers::open_all_zbarriers();
}

// --------------------------------------------------------------------------
// Settings
// --------------------------------------------------------------------------

mm_cycle_accent()
{
    self.mm_accent++;

    if ( self.mm_accent >= level.mm_accents.size )
        self.mm_accent = 0;
}

mm_cycle_rows()
{
    self.mm_max = self.mm_max + 2;

    if ( self.mm_max > 11 )
        self.mm_max = 7;

    self.mm_top = 0;
    self.mm_idx = 0;
    self mm_layout();
}

mm_reset_all()
{
    keys = getarraykeys( self.mm_on );
    i = 0;

    while ( i < keys.size )
    {
        if ( keys[i] != "closeonsel" && self.mm_on[keys[i]] )
        {
            self.mm_on[keys[i]] = 0;
            self mm_apply_toggle( keys[i] );
        }

        i++;
    }
}
